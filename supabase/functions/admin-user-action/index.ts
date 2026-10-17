// Supabase Edge Function: admin-user-action
// Handles two account actions, each available two ways:
//   - "revoke": cancel the Stripe subscription and mark the account
//     canceled. Access is blocked but the user's data (progress, notes,
//     test history) is kept.
//   - "delete": cancel the Stripe subscription, then delete the auth
//     account outright. Every table with a user_id foreign key cascades on
//     delete, so this wipes all of that user's data too.
// A user can call either action on themselves (self-service "cancel
// account" / "delete account & all data" in their Profile screen). An admin
// can call either action on any non-admin user from the admin dashboard.
// Either way the action is written to account_action_log first (while the
// target's email is still resolvable), so a permanently deleted account
// still leaves an audit trail an admin can see.
//
// Needs server-side secrets (STRIPE_SECRET_KEY to cancel billing,
// SUPABASE_SERVICE_ROLE_KEY to read across users and delete an auth
// account), so this can't run as client-side JS or a plain Postgres RPC.

import Stripe from "npm:stripe@17";
import { createClient } from "npm:@supabase/supabase-js@2";

const STRIPE_SECRET_KEY = Deno.env.get("STRIPE_SECRET_KEY") || "";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "";
const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY") || "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";

const stripe = new Stripe(STRIPE_SECRET_KEY, {
  apiVersion: "2024-06-20",
  httpClient: Stripe.createFetchHttpClient(),
});

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const userClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      global: { headers: { Authorization: req.headers.get("Authorization") || "" } },
    });
    const { data: { user: caller }, error: callerErr } = await userClient.auth.getUser();
    if (callerErr || !caller) return json({ error: "not authenticated" }, 401);

    const admin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

    const body = await req.json().catch(() => ({}));
    const target_user_id = body?.target_user_id;
    const action = body?.action;
    if (!target_user_id || (action !== "revoke" && action !== "delete")) {
      return json({ error: "target_user_id and a valid action are required" }, 400);
    }

    const isSelf = target_user_id === caller.id;

    const { data: callerSub } = await admin
      .from("cissp_subscriptions")
      .select("is_admin")
      .eq("user_id", caller.id)
      .maybeSingle();

    if (isSelf) {
      if (callerSub?.is_admin) {
        return json({ error: "admin accounts can't self-service this -- ask another admin" }, 400);
      }
    } else if (!callerSub?.is_admin) {
      return json({ error: "not authorized" }, 403);
    }

    const { data: targetSub } = await admin
      .from("cissp_subscriptions")
      .select("is_admin, stripe_subscription_id")
      .eq("user_id", target_user_id)
      .maybeSingle();
    if (!isSelf && targetSub?.is_admin) {
      return json({ error: "cannot act on another admin account" }, 400);
    }

    let targetEmail: string | null = null;
    try {
      const { data: targetUser } = await admin.auth.admin.getUserById(target_user_id);
      targetEmail = targetUser?.user?.email || null;
    } catch (_e) { /* best-effort for the log entry only */ }

    if (targetSub?.stripe_subscription_id) {
      try {
        await stripe.subscriptions.cancel(targetSub.stripe_subscription_id as string);
      } catch (_e) {
        // Already canceled, or never fully created on Stripe's side -- fine either way.
      }
    }

    await admin.from("account_action_log").insert({
      target_user_id,
      target_email: targetEmail,
      action,
      actor: isSelf ? "self" : "admin",
      actor_email: caller.email || null,
    });

    if (action === "revoke") {
      const { error } = await admin
        .from("cissp_subscriptions")
        .update({ status: "canceled", updated_at: new Date().toISOString() })
        .eq("user_id", target_user_id);
      if (error) throw error;
      return json({ ok: true });
    }

    const { error: delErr } = await admin.auth.admin.deleteUser(target_user_id);
    if (delErr) throw delErr;
    return json({ ok: true });
  } catch (e) {
    return json({ error: String(e) }, 400);
  }
});
