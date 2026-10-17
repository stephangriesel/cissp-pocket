-- Run once in the Supabase SQL editor, THEN re-run admin_dashboard.sql (its
-- admin_list_signups() now also selects the signup_ip column added below --
-- it has to be dropped and recreated there since changing a function's
-- return columns needs DROP FUNCTION first).
--
-- Adds lightweight free-trial abuse visibility: records the IP address a
-- trial signup came from (read from the request headers PostgREST exposes
-- to security-definer functions), so an admin can spot one person spinning
-- up several trial accounts from the same connection. This is visibility,
-- not a hard block -- shared IPs (offices, campuses, families, carrier-grade
-- NAT) are common and would false-positive a real block, so it's surfaced
-- on the admin Signups screen instead of auto-rejecting signups.

alter table public.cissp_subscriptions add column if not exists signup_ip text;

create or replace function public.ensure_cissp_subscription()
returns cissp_subscriptions
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  uid uuid := auth.uid();
  uemail text;
  rec public.cissp_subscriptions;
  ip text;
begin
  if uid is null then
    raise exception 'not authenticated';
  end if;
  select * into rec from public.cissp_subscriptions where user_id = uid;
  if found then
    return rec;
  end if;
  select email into uemail from auth.users where id = uid;
  ip := split_part(coalesce((current_setting('request.headers', true)::json)->>'x-forwarded-for', ''), ',', 1);
  insert into public.cissp_subscriptions (user_id, status, trial_ends_at, is_admin, signup_ip)
  values (
    uid,
    'trialing',
    now() + interval '7 days',
    coalesce(lower(uemail) = any(array['sgriesel@gmail.com']), false),
    nullif(trim(ip), '')
  )
  returning * into rec;
  return rec;
end;
$$;

-- Now re-run admin_dashboard.sql so admin_list_signups() picks up signup_ip.
