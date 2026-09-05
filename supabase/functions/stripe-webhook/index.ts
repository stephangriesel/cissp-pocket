// Supabase Edge Function: stripe-webhook
// Receives Stripe subscription lifecycle events and keeps cissp_subscriptions
// in sync. Verifies Stripe's own signature (no Supabase JWT — verify_jwt = false,
// since Stripe calls this directly).

import Stripe from "npm:stripe@17";
import { createClient } from "npm:@supabase/supabase-js@2";

const STRIPE_SECRET_KEY = Deno.env.get("STRIPE_SECRET_KEY") || "";
const STRIPE_WEBHOOK_SECRET = Deno.env.get("STRIPE_WEBHOOK_SECRET") || "";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";

const stripe = new Stripe(STRIPE_SECRET_KEY, {
  apiVersion: "2024-06-20",
  httpClient: Stripe.createFetchHttpClient(),
});
const admin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

function mapStatus(s: string): string {
  if (s === "trialing") return "trialing";
  if (s === "active") return "active";
  if (s === "past_due" || s === "unpaid" || s === "incomplete") return "past_due";
  return "canceled"; // canceled, incomplete_expired, paused
}

async function upsertFromSubscription(uid: string, subscription: Stripe.Subscription) {
  await admin
    .from("cissp_subscriptions")
    .update({
      status: mapStatus(subscription.status),
      stripe_customer_id: subscription.customer as string,
      stripe_subscription_id: subscription.id,
      current_period_end: new Date(subscription.current_period_end * 1000).toISOString(),
      trial_ends_at: subscription.trial_end ? new Date(subscription.trial_end * 1000).toISOString() : null,
      updated_at: new Date().toISOString(),
    })
    .eq("user_id", uid);
}

Deno.serve(async (req) => {
  const sig = req.headers.get("stripe-signature");
  const body = await req.text();

  let event: Stripe.Event;
  try {
    if (!sig) throw new Error("missing stripe-signature header");
    event = await stripe.webhooks.constructEventAsync(body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    return new Response(`Webhook signature verification failed: ${e}`, { status: 400 });
  }

  try {
    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object as Stripe.Checkout.Session;
        const uid = session.client_reference_id || session.metadata?.supabase_user_id;
        if (uid && session.subscription) {
          const subscription = await stripe.subscriptions.retrieve(session.subscription as string);
          await upsertFromSubscription(uid, subscription);
        }
        break;
      }
      case "customer.subscription.created":
      case "customer.subscription.updated":
      case "customer.subscription.deleted": {
        const subscription = event.data.object as Stripe.Subscription;
        const uid = subscription.metadata?.supabase_user_id;
        if (uid) {
          await upsertFromSubscription(uid, subscription);
        } else {
          // metadata missing (e.g. subscription created outside our Checkout call) — fall back to customer id
          const { data } = await admin
            .from("cissp_subscriptions")
            .select("user_id")
            .eq("stripe_customer_id", subscription.customer as string)
            .maybeSingle();
          if (data) await upsertFromSubscription(data.user_id as string, subscription);
        }
        break;
      }
      default:
        break;
    }
  } catch (e) {
    console.error("stripe-webhook handling error", e);
    return new Response(`error: ${e}`, { status: 500 });
  }

  return new Response(JSON.stringify({ received: true }), {
    headers: { "Content-Type": "application/json" },
  });
});
