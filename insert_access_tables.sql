-- ============================================================
--  Користувачі, ролі та права доступу (Налаштування → Користувачі та доступ)
--
--  app_roles       — ролі (Адміністратор, Керівник, Співробітник, власні)
--  app_role_perms  — рівень доступу ролі до кожного розділу
--  app_users       — профіль користувача Supabase Auth: роль, стан, співробітник
--  app_user_perms  — індивідуальні винятки з прав ролі для конкретного користувача
--
--  Рівні доступу: 0 — немає (розділ прихований), 1 — перегляд,
--                 2 — редагування, 3 — повний (з видаленням).
--
--  Усі наявні користувачі Supabase Auth стають адміністраторами.
--  Нові (зареєстровані не через панель) — неактивні «Співробітники».
--  Скрипт можна запускати повторно.
-- ============================================================

create table if not exists app_roles (
  id          text primary key,
  name        text not null,
  description text,
  is_admin    boolean not null default false,   -- повний доступ до всього, права не перевіряються
  is_system   boolean not null default false,   -- системну роль не можна видалити
  sort        int not null default 0,
  created_at  timestamptz not null default now()
);

create table if not exists app_role_perms (
  role_id  text not null references app_roles(id) on delete cascade,
  section  text not null,
  level    smallint not null default 0 check (level between 0 and 3),
  primary key (role_id, section)
);

create table if not exists app_users (
  id              uuid primary key references auth.users(id) on delete cascade,
  email           text,
  full_name       text,
  role_id         text references app_roles(id) on delete set null,
  is_active       boolean not null default true,
  note            text,
  last_sign_in_at timestamptz,
  created_at      timestamptz not null default now()
);

-- зв'язок із довідником співробітників (тип id беремо з dict_employees)
do $$
declare t text;
begin
  if to_regclass('public.dict_employees') is not null
     and not exists (select 1 from information_schema.columns
                      where table_name = 'app_users' and column_name = 'employee_id') then
    select format_type(atttypid, atttypmod) into t
      from pg_attribute where attrelid = 'public.dict_employees'::regclass and attname = 'id';
    execute format('alter table app_users add column employee_id %s references dict_employees(id) on delete set null', t);
  end if;
end $$;

create table if not exists app_user_perms (
  user_id  uuid not null references app_users(id) on delete cascade,
  section  text not null,
  level    smallint not null check (level between 0 and 3),
  primary key (user_id, section)
);

-- ---------- Ролі за замовчуванням ----------
insert into app_roles (id, name, description, is_admin, is_system, sort) values
  ('admin',    'Адміністратор', 'Повний доступ до всіх розділів і керування користувачами', true,  true, 1),
  ('manager',  'Керівник',      'Редагування робочих розділів, без керування доступом',     false, true, 2),
  ('employee', 'Співробітник',  'Перегляд основних розділів',                                false, true, 3)
on conflict (id) do nothing;

insert into app_role_perms (role_id, section, level)
select r.role_id, s.section,
       case r.role_id
         when 'manager'  then case s.section when 'access' then 0 when 'settings' then 1 else 2 end
         when 'employee' then case when s.section in ('dash','goals','dev','reports','bot') then 1 else 0 end
       end
  from (values ('manager'), ('employee')) r(role_id)
 cross join (values ('dash'),('proc'),('matrix'),('goals'),('company'),('reports'),('analytics'),
                    ('budget'),('dev'),('bot'),('settings'),('access')) s(section)
on conflict (role_id, section) do nothing;

-- ---------- Наявні користувачі → адміністратори ----------
insert into app_users (id, email, full_name, role_id, is_active, last_sign_in_at, created_at)
select u.id, u.email, u.raw_user_meta_data->>'full_name', 'admin', true, u.last_sign_in_at, u.created_at
  from auth.users u
on conflict (id) do nothing;

-- ---------- Синхронізація з auth.users ----------
create or replace function app_users_on_auth_insert() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into app_users (id, email, full_name, role_id, is_active)
  values (new.id, new.email, new.raw_user_meta_data->>'full_name', 'employee', false)
  on conflict (id) do nothing;
  return new;
end $$;

create or replace function app_users_on_auth_update() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  update app_users set email = new.email, last_sign_in_at = new.last_sign_in_at where id = new.id;
  return new;
end $$;

drop trigger if exists app_users_auth_insert on auth.users;
create trigger app_users_auth_insert after insert on auth.users
  for each row execute function app_users_on_auth_insert();

drop trigger if exists app_users_auth_update on auth.users;
create trigger app_users_auth_update after update of email, last_sign_in_at on auth.users
  for each row execute function app_users_on_auth_update();

-- ---------- Перевірка прав (для RLS і RPC) ----------
create or replace function app_is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from app_users u join app_roles r on r.id = u.role_id
                  where u.id = auth.uid() and u.is_active and r.is_admin);
$$;

-- рівень доступу поточного користувача до розділу (0..3)
create or replace function app_level(p_section text) returns int
language sql stable security definer set search_path = public as $$
  select case
    when app_is_admin() then 3
    when not exists (select 1 from app_users where id = auth.uid() and is_active) then 0
    else coalesce(
      (select level from app_user_perms where user_id = auth.uid() and section = p_section),
      (select rp.level from app_users u join app_role_perms rp on rp.role_id = u.role_id
        where u.id = auth.uid() and rp.section = p_section),
      0)
  end;
$$;

-- не дати прибрати останнього активного адміністратора
create or replace function app_users_keep_admin() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from app_users u join app_roles r on r.id = u.role_id
                  where u.is_active and r.is_admin) then
    raise exception 'Має залишитися хоча б один активний адміністратор';
  end if;
  return null;
end $$;

drop trigger if exists app_users_keep_admin on app_users;
create trigger app_users_keep_admin after update or delete on app_users
  for each row execute function app_users_keep_admin();

-- видалення користувача разом з обліковим записом Supabase Auth
create or replace function app_delete_user(p_user uuid) returns void
language plpgsql security definer set search_path = public, auth as $$
begin
  if app_level('access') < 3 then
    raise exception 'Недостатньо прав для видалення користувачів';
  end if;
  if p_user = auth.uid() then
    raise exception 'Не можна видалити власний обліковий запис';
  end if;
  delete from auth.users where id = p_user;
end $$;

revoke all on function app_delete_user(uuid) from public, anon;
grant execute on function app_delete_user(uuid) to authenticated;

-- ---------- RLS ----------
alter table app_roles      enable row level security;
alter table app_role_perms enable row level security;
alter table app_users      enable row level security;
alter table app_user_perms enable row level security;

do $$
declare t text;
begin
  foreach t in array array['app_roles','app_role_perms','app_users','app_user_perms'] loop
    execute format('drop policy if exists "read" on %I', t);
    execute format('drop policy if exists "write" on %I', t);
    execute format('drop policy if exists "update" on %I', t);
    execute format('drop policy if exists "remove" on %I', t);
    execute format('create policy "read" on %I for select to authenticated using (true)', t);
    execute format('create policy "write" on %I for insert to authenticated with check (app_level(''access'') >= 2)', t);
    execute format('create policy "update" on %I for update to authenticated using (app_level(''access'') >= 2) with check (app_level(''access'') >= 2)', t);
    execute format('create policy "remove" on %I for delete to authenticated using (app_level(''access'') >= 3)', t);
  end loop;
end $$;
