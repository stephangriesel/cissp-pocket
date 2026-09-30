-- Run once in the Supabase SQL editor to power the in-app "Signups" admin
-- screen (the 👥 nav button, visible only to accounts with is_admin = true).
--
-- Lets a signed-in admin see every user's email, signup date, and
-- subscription status via one RPC call. Runs as security definer specifically
-- so it can read auth.users (normally locked down) and every row of
-- cissp_subscriptions (normally RLS'd to each user's own row) -- but it
-- checks the CALLER is an admin before returning anything, so a non-admin
-- calling this RPC gets an error, not another user's data.
create or replace function public.admin_list_signups()
returns table (
  id uuid,
  email text,
  created_at timestamptz,
  is_admin boolean,
  status text,
  trial_ends_at timestamptz
)
language plpgsql
security definer
set search_path = public, auth
as $$
begin
  if not exists (
    select 1 from public.cissp_subscriptions s
    where s.user_id = auth.uid() and s.is_admin = true
  ) then
    raise exception 'not authorized';
  end if;

  return query
  select u.id, u.email, u.created_at, coalesce(s.is_admin, false), s.status, s.trial_ends_at
  from auth.users u
  left join public.cissp_subscriptions s on s.user_id = u.id
  order by u.created_at desc;
end;
$$;

grant execute on function public.admin_list_signups() to authenticated;
