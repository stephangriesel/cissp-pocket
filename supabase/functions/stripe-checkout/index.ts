// Supabase Edge Function: stripe-checkout
// Creates a Stripe Checkout Session (subscription mode) for the signed-in user
// and returns its URL. Requires a valid Supabase JWT (verify_jwt = true).

import Stripe from "npm:stripe@17";
import { createClient } from "npm:@supabase/supabase-js@2";

const STRIPE_SECRET_KEY = Deno.env.get("STRIPE_SECRET_KEY") || "";
const STRIPE_PRICE_ID = Deno.env.get("STRIPE_PRICE_ID") || "";
const SITE_URL = Deno.env.get("SITE_URL") || "";
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

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const userClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      global: { headers: { Authorization: req.headers.get("Authorization") || "" } },
    });
    const { data: { user }, error: userErr } = await userClient.auth.getUser();
    if (userErr || !user || !user.email) {
      return new Response(JSON.stringify({ error: "not authenticated" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const admin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
    const { data: sub } = await admin
      .from("cissp_subscriptions")
      .select("stripe_customer_id, trial_ends_at")
      .eq("user_id", user.id)
      .maybeSingle();

    let customerId = sub?.stripe_customer_id as string | undefined;
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: user.email,
        metadata: { supabase_user_id: user.id },
      });
      customerId = customer.id;
      await admin.from("cissp_subscriptions").update({ stripe_customer_id: customerId }).eq("user_id", user.id);
    }

    // If the user still has more than a day left on their app-level free
    // trial, carry it over as the Stripe trial so checking out early doesn't
    // start a second trial (or bill them) on top of the one they're already in.
    let trialEnd: number | undefined;
    if (sub?.trial_ends_at) {
      const t = Math.floor(new Date(sub.trial_ends_at as string).getTime() / 1000);
      if (t > Math.floor(Date.now() / 1000) + 86400) trialEnd = t;
    }

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer: customerId,
      line_items: [{ price: STRIPE_PRICE_ID, quantity: 1 }],
      subscription_data: {
        metadata: { supabase_user_id: user.id },
        ...(trialEnd ? { trial_end: trialEnd } : {}),
      },
      client_reference_id: user.id,
      allow_promotion_codes: true,
      success_url: `${SITE_URL}/?billing=success`,
      cancel_url: `${SITE_URL}/?billing=cancel`,
    });

    return new Response(JSON.stringify({ url: session.url }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: String(e) }), {
      status: 400,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
