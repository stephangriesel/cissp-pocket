// Supabase Edge Function: verify-password
// Checks a submitted password against a secret stored in Supabase, server-side only.
// Returns a simple signed token (HMAC) the client can store and present on future loads.

import { createHmac } from "node:crypto";

const APP_PASSWORD = Deno.env.get("APP_PASSWORD") || "";
const SIGNING_SECRET = Deno.env.get("SIGNING_SECRET") || "";

function sign(payload: string): string {
  return createHmac("sha256", SIGNING_SECRET).update(payload).digest("hex");
}

Deno.serve(async (req) => {
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
  };

  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { password, token } = await req.json();

    // Path 1: verify an existing stored token (used on page load to confirm still-valid session)
    if (token) {
      const [payload, sig] = token.split(".");
      if (payload && sig && sign(payload) === sig) {
        return new Response(JSON.stringify({ valid: true }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ valid: false }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Path 2: verify a freshly submitted password, issue a new token
    if (password === APP_PASSWORD && APP_PASSWORD.length > 0) {
      const payload = `ok.${Date.now()}`;
      const sig = sign(payload);
      const issuedToken = `${payload}.${sig}`;
      return new Response(JSON.stringify({ valid: true, token: issuedToken }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ valid: false }), {
      status: 401,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ valid: false, error: "bad request" }), {
      status: 400,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
