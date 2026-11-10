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

-- Admin area. Admins are listed by account id; the table is not readable from the browser.
create table if not exists public.admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  added_at timestamptz not null default now()
);
alter table public.admins enable row level security;
revoke all on public.admins from anon, authenticated;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.admins a where a.user_id = (select auth.uid()));
$$;

create or replace function public.admin_list_users()
returns table (id uuid, email text, created_at timestamptz, last_sign_in_at timestamptz,
               plays int, formations int, playbook_name text, last_saved timestamptz)
language plpgsql stable security definer set search_path = '' as $$
begin
  if not public.is_admin() then
    raise exception 'not authorized' using errcode = '42501';
  end if;
  return query
    select u.id, u.email::text, u.created_at, u.last_sign_in_at,
      coalesce(jsonb_array_length(case when jsonb_typeof(p.data->'plays') = 'array' then p.data->'plays' end), 0),
      coalesce(jsonb_array_length(case when jsonb_typeof(p.data->'customFormations') = 'array' then p.data->'customFormations' end), 0),
      p.data->>'name', p.updated_at
    from auth.users u left join public.playbooks p on p.user_id = u.id
    order by u.created_at desc;
end;
$$;
revoke all on function public.is_admin() from public, anon;
revoke all on function public.admin_list_users() from public, anon;
grant execute on function public.is_admin() to authenticated;
grant execute on function public.admin_list_users() to authenticated;

-- To make an account an admin (run in the Supabase SQL editor, after that account has signed up):
--   insert into public.admins (user_id) select id from auth.users where email = 'you@example.com';

-- ---------------------------------------------------------------
-- View-only share links (one per coach). The viewer page calls
-- get_share(id) with the public key; the id is the secret.
-- ---------------------------------------------------------------
create table if not exists public.shares (
  id text primary key default encode(extensions.gen_random_bytes(9), 'hex'),
  user_id uuid not null unique default auth.uid() references auth.users (id) on delete cascade,
  data jsonb not null check (pg_column_size(data) < 1500000),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.shares enable row level security;
drop policy if exists "shares own rows" on public.shares;
create policy "shares own rows" on public.shares for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

create or replace function public.get_share(sid text)
returns jsonb language sql stable security definer set search_path = public as $$
  select data from public.shares where id = sid
$$;
revoke all on function public.get_share(text) from public;
grant execute on function public.get_share(text) to anon, authenticated;

-- ---------------------------------------------------------------
-- In-app feedback. Anyone can send a note; only admins can read them
-- (through admin_list_feedback on the admin page).
-- ---------------------------------------------------------------
create table if not exists public.feedback (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  user_id uuid default auth.uid() references auth.users (id) on delete set null,
  email text check (char_length(email) <= 200),
  message text not null check (char_length(message) between 3 and 4000),
  page text check (char_length(page) <= 200),
  agent text check (char_length(agent) <= 300)
);
alter table public.feedback enable row level security;
revoke all on public.feedback from anon, authenticated;
grant insert (email, message, page, agent) on public.feedback to anon, authenticated;
drop policy if exists "feedback insert" on public.feedback;
create policy "feedback insert" on public.feedback for insert to anon, authenticated with check (true);

create or replace function public.admin_list_feedback()
returns table (id bigint, created_at timestamptz, email text, account_email text, message text, page text, agent text)
language plpgsql stable security definer set search_path = '' as $$
begin
  if not public.is_admin() then
    raise exception 'not authorized' using errcode = '42501';
  end if;
  return query
    select f.id, f.created_at, f.email, u.email::text, f.message, f.page, f.agent
    from public.feedback f left join auth.users u on u.id = f.user_id
    order by f.created_at desc limit 500;
end;
$$;
revoke all on function public.admin_list_feedback() from public, anon;
grant execute on function public.admin_list_feedback() to authenticated;
