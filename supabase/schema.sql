-- PlayBand: one playbook per account. Run once in the Supabase SQL editor.
create table if not exists public.playbooks (
  user_id uuid primary key references auth.users(id) on delete cascade,
  data jsonb not null,
  updated_at timestamptz not null default now(),
  constraint playbooks_size check (pg_column_size(data) < 2000000)
);
alter table public.playbooks enable row level security;
revoke all on public.playbooks from anon;
grant select, insert, update, delete on public.playbooks to authenticated;
create policy "playbooks_select_own" on public.playbooks for select to authenticated using ((select auth.uid()) = user_id);
create policy "playbooks_insert_own" on public.playbooks for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "playbooks_update_own" on public.playbooks for update to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "playbooks_delete_own" on public.playbooks for delete to authenticated using ((select auth.uid()) = user_id);
