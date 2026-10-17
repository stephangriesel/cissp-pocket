-- Run once in the Supabase SQL editor. Keeps an audit trail of "revoke
-- access" / "delete everything" actions -- both self-service (a user acting
-- on their own account) and admin-triggered (an admin acting on someone
-- else's) -- so a permanently deleted account still leaves a record behind.
--
-- target_user_id/target_email are plain columns, NOT a foreign key to
-- auth.users: a real FK (even with on delete cascade) would either block the
-- delete or erase this very row when the user is removed, defeating the
-- point of an audit log.
create table if not exists public.account_action_log (
  id uuid primary key default gen_random_uuid(),
  target_user_id uuid,
  target_email text,
  action text not null check (action in ('revoke', 'delete')),
  actor text not null check (actor in ('self', 'admin')),
  actor_email text,
  created_at timestamptz not null default now()
);

create index if not exists account_action_log_created_at_idx
  on public.account_action_log (created_at desc);

-- Locked down by default -- only the service role (used by the
-- admin-user-action edge function to write) and the security-definer RPC
-- below (used by the admin UI to read) can touch this table.
alter table public.account_action_log enable row level security;

create or replace function public.admin_list_account_action_log()
returns table (
  id uuid,
  target_user_id uuid,
  target_email text,
  action text,
  actor text,
  actor_email text,
  created_at timestamptz
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
  select l.id, l.target_user_id, l.target_email, l.action, l.actor, l.actor_email, l.created_at
  from public.account_action_log l
  order by l.created_at desc
  limit 100;
end;
$$;

grant execute on function public.admin_list_account_action_log() to authenticated;
