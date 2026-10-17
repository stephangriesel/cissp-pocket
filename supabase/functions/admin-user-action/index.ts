// Supabase Edge Function: admin-user-action
// Lets a signed-in admin either revoke a user's access (cancel their Stripe
// subscription, mark them canceled -- their data is kept, they just lose
// access) or permanently delete a user (cancel their subscription, then
// delete their auth account; every table with a user_id foreign key cascades
// on delete, so this also wipes their progress, notes, test history, etc).
//
// Both actions need server-side secrets (STRIPE_SECRET_KEY to cancel billing,
// SUPABASE_SERVICE_ROLE_KEY to read across users and delete an auth account),
// so this can't run as client-side JS or a plain Postgres RPC.

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

    const { data: callerSub } = await admin
      .from("cissp_subscriptions")
      .select("is_admin")
      .eq("user_id", caller.id)
      .maybeSingle();
    if (!callerSub?.is_admin) return json({ error: "not authorized" }, 403);

    const body = await req.json().catch(() => ({}));
    const target_user_id = body?.target_user_id;
    const action = body?.action;
    if (!target_user_id || (action !== "revoke" && action !== "delete")) {
      return json({ error: "target_user_id and a valid action are required" }, 400);
    }
    if (target_user_id === caller.id) {
      return json({ error: "cannot act on your own account" }, 400);
    }

    const { data: targetSub } = await admin
      .from("cissp_subscriptions")
      .select("is_admin, stripe_subscription_id")
      .eq("user_id", target_user_id)
      .maybeSingle();
    if (targetSub?.is_admin) {
      return json({ error: "cannot act on another admin account" }, 400);
    }

    if (targetSub?.stripe_subscription_id) {
      try {
        await stripe.subscriptions.cancel(targetSub.stripe_subscription_id as string);
      } catch (_e) {
        // Already canceled, or never fully created on Stripe's side -- fine either way.
      }
    }

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
