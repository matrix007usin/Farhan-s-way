-- =====================================================================
--  Farhan's Way : database setup for Supabase
--  Paste this whole file into  Supabase > SQL Editor > New query  and press RUN.
--  It is safe to run again later (it never deletes your clients or workouts).
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;
create schema if not exists fw_private;

-- ---------- tables ----------------------------------------------------
create table if not exists public.fw_users (
  id         text primary key,                      -- 'admin' or the client's mobile number
  role       text not null check (role in ('admin','client')),
  pw_hash    text not null,                         -- scrambled password, never the real one
  data       jsonb not null default '{}'::jsonb,    -- name, program, week, body details ...
  created_at timestamptz not null default now()
);
create table if not exists public.fw_programs  (id text primary key, data jsonb not null);
create table if not exists public.fw_templates (id text primary key, owner text not null, data jsonb not null);
create table if not exists public.fw_logs      (id text primary key, owner text not null, day text not null, ts bigint not null, data jsonb not null);
alter table public.fw_logs add column if not exists upd bigint not null default 0;
create table if not exists public.fw_drafts    (owner text primary key, data jsonb not null);
create table if not exists public.fw_live      (owner text primary key, data jsonb not null);
create table if not exists public.fw_settings  (owner text not null, key text not null, data jsonb not null, primary key (owner, key));
create table if not exists public.fw_sessions  (token_hash text primary key, uid text not null references public.fw_users(id) on delete cascade, expires_at timestamptz not null, created_at timestamptz not null default now());
create table if not exists public.fw_attempts  (id text not null, at timestamptz not null default now());

create index if not exists fw_templates_owner on public.fw_templates (owner);
create index if not exists fw_logs_owner_ts   on public.fw_logs (owner, ts desc);
create index if not exists fw_logs_ts         on public.fw_logs (ts desc);
create index if not exists fw_logs_upd        on public.fw_logs (upd);
create index if not exists fw_sessions_uid    on public.fw_sessions (uid);
create index if not exists fw_attempts_id_at  on public.fw_attempts (id, at);

-- ---------- lock every table: nobody can read or write them directly ---
do $$
declare t text;
begin
  foreach t in array array['fw_users','fw_programs','fw_templates','fw_logs','fw_drafts','fw_live','fw_settings','fw_sessions','fw_attempts'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('revoke all on public.%I from anon, authenticated', t);
  end loop;
end $$;
revoke all on schema fw_private from public;

-- ---------- helpers (private) ------------------------------------------
create or replace function fw_private.pub(u public.fw_users) returns jsonb
language sql immutable as $$ select u.data || jsonb_build_object('id', u.id, 'role', u.role) $$;

create or replace function fw_private.who(p_token text, p_allow_must boolean default false)
returns public.fw_users language plpgsql security definer set search_path = public, extensions as $$
declare u public.fw_users; h text;
begin
  h := encode(digest(coalesce(p_token,''), 'sha256'), 'hex');
  select usr.* into u from public.fw_sessions s join public.fw_users usr on usr.id = s.uid
   where s.token_hash = h and s.expires_at > now();
  if not found then raise exception 'auth'; end if;
  if u.role = 'client' and coalesce(u.data->>'active','true') = 'false' then raise exception 'paused'; end if;
  if coalesce(u.data->>'must','false') = 'true' and not p_allow_must then raise exception 'must_change'; end if;
  update public.fw_sessions set expires_at = now() + interval '60 days'
   where token_hash = h and expires_at < now() + interval '50 days';
  return u;
end $$;

create or replace function fw_private.now_ms() returns bigint language sql stable as $$ select (extract(epoch from clock_timestamp()) * 1000)::bigint $$;

-- ---------- sign in / out ----------------------------------------------
create or replace function public.fw_login(p_id text, p_pw text, p_role text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare u public.fw_users; tok text; n int; g int;
begin
  p_id := lower(trim(coalesce(p_id,'')));
  delete from public.fw_attempts where at < now() - interval '1 day';
  select count(*) into n from public.fw_attempts where id = p_id and at > now() - interval '15 minutes';
  select count(*) into g from public.fw_attempts where at > now() - interval '5 minutes';
  if n >= 8 or g >= 300 then return jsonb_build_object('ok', false, 'err', 'locked'); end if;
  select * into u from public.fw_users where id = p_id and role = coalesce(p_role,'client');
  if not found or u.pw_hash <> crypt(coalesce(p_pw,''), u.pw_hash) then
    insert into public.fw_attempts(id) values (p_id);
    return jsonb_build_object('ok', false, 'err', 'bad');
  end if;
  if u.role = 'client' and coalesce(u.data->>'active','true') = 'false' then
    return jsonb_build_object('ok', false, 'err', 'paused');
  end if;
  delete from public.fw_attempts where id = p_id;
  tok := encode(gen_random_bytes(32), 'hex');
  insert into public.fw_sessions(token_hash, uid, expires_at)
  values (encode(digest(tok,'sha256'),'hex'), u.id, now() + interval '60 days');
  return jsonb_build_object('ok', true, 'token', tok, 'must', coalesce(u.data->>'must','false') = 'true', 'role', u.role, 'id', u.id, 'name', u.data->>'name');
end $$;

create or replace function public.fw_logout(p_token text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
begin
  delete from public.fw_sessions where token_hash = encode(digest(coalesce(p_token,''),'sha256'),'hex');
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.fw_change_password(p_token text, p_new text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare u public.fw_users; h text;
begin
  u := fw_private.who(p_token, true);
  if length(coalesce(p_new,'')) < 6 or lower(p_new) = 'admin' then raise exception 'weak'; end if;
  h := encode(digest(p_token,'sha256'),'hex');
  update public.fw_users set pw_hash = crypt(p_new, gen_salt('bf')), data = data || '{"must": false}'::jsonb where id = u.id;
  delete from public.fw_sessions where uid = u.id and token_hash <> h;
  return jsonb_build_object('ok', true);
end $$;

-- ---------- read ----------------------------------------------------------
create or replace function public.fw_load(p_token text, p_days int default 45) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare u public.fw_users; since bigint;
begin
  u := fw_private.who(p_token);
  since := fw_private.now_ms() - greatest(coalesce(p_days,45),1)::bigint * 86400000;
  if u.role = 'admin' then
    return jsonb_build_object(
      'now', fw_private.now_ms(),
      'me', fw_private.pub(u),
      'users', coalesce((select jsonb_agg(fw_private.pub(x) order by x.created_at) from public.fw_users x), '[]'::jsonb),
      'programs', coalesce((select jsonb_agg(p.data) from public.fw_programs p), '[]'::jsonb),
      'templates', coalesce((select jsonb_agg(t.data) from public.fw_templates t where t.owner = u.id), '[]'::jsonb),
      'logs', coalesce((select jsonb_agg(l.data order by l.ts desc) from public.fw_logs l where l.ts > since), '[]'::jsonb),
      'drafts', '{}'::jsonb,
      'live', coalesce((select jsonb_object_agg(v.owner, v.data) from public.fw_live v), '{}'::jsonb),
      'custom', coalesce((select data from public.fw_settings where owner = u.id and key = 'custom'), '[]'::jsonb),
      'flags', coalesce((select data from public.fw_settings where owner = u.id and key = 'flags'), '{}'::jsonb));
  end if;
  return jsonb_build_object(
    'now', fw_private.now_ms(),
    'me', fw_private.pub(u),
    'users', jsonb_build_array(fw_private.pub(u)),
    'programs', coalesce((select jsonb_agg(p.data) from public.fw_programs p where p.id = u.data->>'program'), '[]'::jsonb),
    'templates', coalesce((select jsonb_agg(t.data) from public.fw_templates t where t.owner = u.id), '[]'::jsonb),
    'logs', coalesce((select jsonb_agg(l.data order by l.ts desc) from public.fw_logs l where l.owner = u.id), '[]'::jsonb),
    'drafts', coalesce((select jsonb_object_agg(d.owner, d.data) from public.fw_drafts d where d.owner = u.id), '{}'::jsonb),
    'live', coalesce((select jsonb_object_agg(v.owner, v.data) from public.fw_live v where v.owner = u.id), '{}'::jsonb),
    'custom', coalesce((select data from public.fw_settings where owner = u.id and key = 'custom'), '[]'::jsonb),
    'flags', coalesce((select data from public.fw_settings where owner = u.id and key = 'flags'), '{}'::jsonb));
end $$;

-- quick refresh: the trainer gets live sessions + new workouts; a client gets their latest plan
create or replace function public.fw_poll(p_token text, p_since bigint default 0) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare u public.fw_users;
begin
  u := fw_private.who(p_token);
  if u.role = 'admin' then
    return jsonb_build_object(
      'now', fw_private.now_ms(),
      'users', coalesce((select jsonb_agg(fw_private.pub(x) order by x.created_at) from public.fw_users x), '[]'::jsonb),
      'live', coalesce((select jsonb_object_agg(v.owner, v.data) from public.fw_live v), '{}'::jsonb),
      'logs', coalesce((select jsonb_agg(z.data) from (select l.data from public.fw_logs l where l.upd > coalesce(p_since,0) order by l.upd limit 300) z), '[]'::jsonb));
  end if;
  return jsonb_build_object(
    'now', fw_private.now_ms(),
    'me', fw_private.pub(u),
    'programs', coalesce((select jsonb_agg(p.data) from public.fw_programs p where p.id = u.data->>'program'), '[]'::jsonb));
end $$;

create or replace function public.fw_admin_client_logs(p_token text, p_cid text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare u public.fw_users;
begin
  u := fw_private.who(p_token);
  if u.role <> 'admin' then raise exception 'forbidden'; end if;
  return coalesce((select jsonb_agg(l.data order by l.ts desc) from public.fw_logs l where l.owner = p_cid), '[]'::jsonb);
end $$;

-- ---------- write ---------------------------------------------------------
create or replace function public.fw_push(p_token text, p_changes jsonb) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare u public.fw_users; adm boolean; el jsonb; rid text; patch jsonb; own text;
begin
  u := fw_private.who(p_token);
  adm := (u.role = 'admin');
  if pg_column_size(p_changes) > 4000000 then raise exception 'too_big'; end if;

  -- people: the trainer may change anything about a client except id, role and password;
  -- a client may only change their own rest time, profile and body measurements
  for el in select value from jsonb_array_elements(coalesce(p_changes->'users'->'up', '[]'::jsonb)) loop
    rid := el->>'id'; patch := coalesce(el->'patch', '{}'::jsonb);
    if not adm and rid <> u.id then raise exception 'forbidden'; end if;
    if adm then
      patch := patch - 'id' - 'role' - 'pw' - 'must';
    else
      select coalesce(jsonb_object_agg(e.key, e.value), '{}'::jsonb) into patch
        from jsonb_each(patch) e where e.key in ('rest','profile','body');
    end if;
    update public.fw_users set data = data || patch where id = rid;
    if not found then raise exception 'no_such_user'; end if;
  end loop;

  -- programs: trainer only
  if jsonb_array_length(coalesce(p_changes->'programs'->'up','[]'::jsonb)) > 0
     or jsonb_array_length(coalesce(p_changes->'programs'->'del','[]'::jsonb)) > 0 then
    if not adm then raise exception 'forbidden'; end if;
  end if;
  for el in select value from jsonb_array_elements(coalesce(p_changes->'programs'->'up', '[]'::jsonb)) loop
    insert into public.fw_programs(id, data) values (el->>'id', el)
    on conflict (id) do update set data = excluded.data;
  end loop;
  delete from public.fw_programs where id in (select jsonb_array_elements_text(coalesce(p_changes->'programs'->'del','[]'::jsonb)));

  -- templates
  for el in select value from jsonb_array_elements(coalesce(p_changes->'templates'->'up', '[]'::jsonb)) loop
    own := case when adm then coalesce(el->>'cid', u.id) else u.id end;
    insert into public.fw_templates(id, owner, data) values (el->>'id', own, el || jsonb_build_object('cid', own))
    on conflict (id) do update set data = excluded.data where public.fw_templates.owner = excluded.owner;
  end loop;
  delete from public.fw_templates where id in (select jsonb_array_elements_text(coalesce(p_changes->'templates'->'del','[]'::jsonb)))
    and (adm or owner = u.id);

  -- workout logs (a client can add their own; only the trainer can delete)
  for el in select value from jsonb_array_elements(coalesce(p_changes->'logs'->'up', '[]'::jsonb)) loop
    own := case when adm then coalesce(el->>'cid', u.id) else u.id end;
    insert into public.fw_logs(id, owner, day, ts, data, upd)
    values (el->>'id', own, coalesce(el->>'date', ''), coalesce((el->>'ts')::bigint, fw_private.now_ms()), el || jsonb_build_object('cid', own), fw_private.now_ms())
    on conflict (id) do update set day = excluded.day, ts = excluded.ts, data = excluded.data, upd = excluded.upd where public.fw_logs.owner = excluded.owner;
  end loop;
  if jsonb_array_length(coalesce(p_changes->'logs'->'del','[]'::jsonb)) > 0 then
    if not adm then raise exception 'forbidden'; end if;
    delete from public.fw_logs where id in (select jsonb_array_elements_text(p_changes->'logs'->'del'));
  end if;

  -- workout in progress, and the "training now" signal
  for el in select value from jsonb_array_elements(coalesce(p_changes->'drafts'->'up', '[]'::jsonb)) loop
    own := case when adm then coalesce(el->>'owner', u.id) else u.id end;
    insert into public.fw_drafts(owner, data) values (own, el->'data')
    on conflict (owner) do update set data = excluded.data;
  end loop;
  delete from public.fw_drafts where owner in (select jsonb_array_elements_text(coalesce(p_changes->'drafts'->'del','[]'::jsonb))) and (adm or owner = u.id);

  for el in select value from jsonb_array_elements(coalesce(p_changes->'live'->'up', '[]'::jsonb)) loop
    own := case when adm then coalesce(el->>'owner', u.id) else u.id end;
    insert into public.fw_live(owner, data) values (own, el->'data')
    on conflict (owner) do update set data = excluded.data;
  end loop;
  delete from public.fw_live where owner in (select jsonb_array_elements_text(coalesce(p_changes->'live'->'del','[]'::jsonb))) and (adm or owner = u.id);

  -- personal settings (custom exercises ...)
  for el in select value from jsonb_array_elements(coalesce(p_changes->'settings'->'up', '[]'::jsonb)) loop
    insert into public.fw_settings(owner, key, data) values (u.id, el->>'key', el->'data')
    on conflict (owner, key) do update set data = excluded.data;
  end loop;
  delete from public.fw_settings where owner = u.id and key in (select jsonb_array_elements_text(coalesce(p_changes->'settings'->'del','[]'::jsonb)));

  return jsonb_build_object('ok', true);
end $$;

-- ---------- trainer-only account tools ----------------------------------------
create or replace function public.fw_admin_create_client(p_token text, p_id text, p_data jsonb) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare u public.fw_users; cid text;
begin
  u := fw_private.who(p_token);
  if u.role <> 'admin' then raise exception 'forbidden'; end if;
  cid := lower(trim(coalesce(p_id,'')));
  if cid !~ '^[0-9]{6,15}$' then return jsonb_build_object('ok', false, 'err', 'bad_id'); end if;
  if exists (select 1 from public.fw_users where id = cid) then return jsonb_build_object('ok', false, 'err', 'exists'); end if;
  insert into public.fw_users(id, role, pw_hash, data)
  values (cid, 'client', crypt('admin', gen_salt('bf')), coalesce(p_data,'{}'::jsonb) - 'id' - 'role' - 'pw' || '{"must": true, "active": true}'::jsonb);
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.fw_admin_reset_password(p_token text, p_cid text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare u public.fw_users;
begin
  u := fw_private.who(p_token);
  if u.role <> 'admin' then raise exception 'forbidden'; end if;
  if p_cid = u.id then raise exception 'forbidden'; end if;
  update public.fw_users set pw_hash = crypt('admin', gen_salt('bf')), data = data || '{"must": true}'::jsonb where id = p_cid and role = 'client';
  if not found then raise exception 'no_such_user'; end if;
  delete from public.fw_sessions where uid = p_cid;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.fw_admin_delete_client(p_token text, p_cid text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare u public.fw_users;
begin
  u := fw_private.who(p_token);
  if u.role <> 'admin' then raise exception 'forbidden'; end if;
  if not exists (select 1 from public.fw_users where id = p_cid and role = 'client') then raise exception 'no_such_user'; end if;
  delete from public.fw_logs      where owner = p_cid;
  delete from public.fw_templates where owner = p_cid;
  delete from public.fw_drafts    where owner = p_cid;
  delete from public.fw_live      where owner = p_cid;
  delete from public.fw_settings  where owner = p_cid;
  delete from public.fw_users     where id = p_cid and role = 'client';
  return jsonb_build_object('ok', true);
end $$;

-- ---------- who may call what ---------------------------------------------------
do $$
declare f text;
begin
  foreach f in array array[
    'fw_login(text,text,text)','fw_logout(text)','fw_change_password(text,text)','fw_load(text,int)','fw_poll(text,bigint)',
    'fw_admin_client_logs(text,text)','fw_push(text,jsonb)','fw_admin_create_client(text,text,jsonb)',
    'fw_admin_reset_password(text,text)','fw_admin_delete_client(text,text)'] loop
    execute format('revoke all on function public.%s from public', f);
    execute format('grant execute on function public.%s to anon, authenticated', f);
  end loop;
end $$;

-- ---------- the trainer account (first sign-in forces a new password) -----------------
insert into public.fw_users(id, role, pw_hash, data)
values ('admin', 'admin', extensions.crypt('1235813', extensions.gen_salt('bf')), '{"name":"Coach Farhan","active":true,"must":true}'::jsonb)
on conflict (id) do nothing;

notify pgrst, 'reload schema';
