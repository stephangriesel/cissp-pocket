// Supabase Edge Function: notify-signup
// Emails the admin whenever a new user finishes sign-up. Invoked by a database
// trigger on cissp_subscriptions (INSERT) -- see supabase/sql/notify_signup.sql
// -- not by the browser, so there's no Supabase user JWT to check. Instead it
// verifies a shared secret the trigger sends in a custom header.

const RESEND_API_KEY = Deno.env.get("RESEND_API_KEY") || "";
const SIGNUP_WEBHOOK_SECRET = Deno.env.get("SIGNUP_WEBHOOK_SECRET") || "";
const ADMIN_EMAIL = Deno.env.get("ADMIN_EMAIL") || "sgriesel@gmail.com";
// Resend's shared sandbox sender -- works with no domain setup, but only
// delivers to the Resend account's own verified email address. Once a sending
// domain is verified in Resend, set NOTIFY_FROM_EMAIL to an address on it
// (e.g. "CISSP Pocket Trainer <notifications@yourdomain.com>") to email any
// ADMIN_EMAIL address, not just the Resend account owner's.
const FROM_EMAIL = Deno.env.get("NOTIFY_FROM_EMAIL") || "onboarding@resend.dev";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "content-type, x-webhook-secret",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405, headers: corsHeaders });
  }

  if (!SIGNUP_WEBHOOK_SECRET || req.headers.get("x-webhook-secret") !== SIGNUP_WEBHOOK_SECRET) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  try {
    const body = await req.json();
    // Supabase database webhooks wrap the row as { record: {...} }; the SQL
    // trigger in notify_signup.sql posts the same shape so this works either way.
    const record = body.record || body;
    const email = record.email || "(no email on file)";
    const userId = record.user_id || record.id || "";
    const createdAt = record.created_at || new Date().toISOString();

    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: FROM_EMAIL,
        to: ADMIN_EMAIL,
        subject: `New signup: ${email}`,
        html: `<p>A new user just signed up for CISSP Pocket Trainer.</p>
<p><strong>Email:</strong> ${email}<br>
<strong>User ID:</strong> ${userId}<br>
<strong>Signed up at:</strong> ${createdAt}</p>`,
      }),
    });

    if (!res.ok) {
      const text = await res.text();
      return new Response(JSON.stringify({ error: text }), {
        status: 502,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ ok: true }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: String(e) }), {
      status: 400,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
