-- Run once in the Supabase SQL editor to email the admin whenever a new user
-- finishes sign-up. Fires from a database trigger on cissp_subscriptions
-- (a row is inserted there exactly once per user, the first time
-- ensure_cissp_subscription() runs for them) rather than on auth.users, so it
-- only fires for users who actually completed sign-up, not every raw auth
-- event.
--
-- BEFORE running this:
--  1. Deploy the notify-signup Edge Function (supabase/functions/notify-signup).
--  2. Create a free account at resend.com and grab an API key.
--  3. Set these Edge Function secrets (Dashboard -> Edge Functions -> Secrets,
--     or `supabase secrets set NAME=value`):
--       RESEND_API_KEY        - from Resend
--       SIGNUP_WEBHOOK_SECRET - make up any random string
--       ADMIN_EMAIL           - optional, defaults to sgriesel@gmail.com
--       NOTIFY_FROM_EMAIL     - optional; until you verify a sending domain in
--                               Resend, leave unset -- it falls back to
--                               Resend's shared sandbox sender, which only
--                               delivers to the email address your Resend
--                               account itself is registered under
--  4. Replace the two placeholders below (project ref + the SAME
--     SIGNUP_WEBHOOK_SECRET value you set as a secret in step 3) before
--     running this file.

create extension if not exists pg_net with schema extensions;

create or replace function public.notify_new_signup()
returns trigger
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  user_email text;
begin
  select email into user_email from auth.users where id = new.user_id;

  perform net.http_post(
    url := 'https://YOUR-PROJECT-REF.supabase.co/functions/v1/notify-signup',
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'x-webhook-secret', 'YOUR-SIGNUP-WEBHOOK-SECRET'
    ),
    body := jsonb_build_object(
      'user_id', new.user_id,
      'email', user_email,
      'created_at', now()
    )
  );
  return new;
end;
$$;

drop trigger if exists trg_notify_new_signup on public.cissp_subscriptions;
create trigger trg_notify_new_signup
  after insert on public.cissp_subscriptions
  for each row execute function public.notify_new_signup();
