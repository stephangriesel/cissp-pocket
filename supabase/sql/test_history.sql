-- Run once in the Supabase SQL editor to enable the Test History feature.
create table if not exists public.test_history (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  taken_at timestamptz not null default now(),
  correct int not null,
  total int not null,
  pct int not null,
  passed boolean not null,
  timed_out boolean not null default false,
  domains jsonb not null default '{}'::jsonb
);

create index if not exists test_history_user_id_taken_at_idx
  on public.test_history (user_id, taken_at desc);

alter table public.test_history enable row level security;

create policy "Users can view their own test history"
  on public.test_history for select
  using (auth.uid() = user_id);

create policy "Users can insert their own test history"
  on public.test_history for insert
  with check (auth.uid() = user_id);

create policy "Users can delete their own test history"
  on public.test_history for delete
  using (auth.uid() = user_id);
