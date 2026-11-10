-- ============================================================
--  Ролі v2: обсяг даних, чутливі дозволи, Власник, шаблони ролей
--
--  1. Обсяг даних для розділу в ролі (app_role_perms.scope):
--       own  — лише записи про себе (співробітник, прив'язаний до користувача)
--       unit — свої підрозділи разом із дочірніми: де людина керівник
--              в оргструктурі, а якщо ніде — її основний підрозділ
--       all  — уся компанія (як було)
--     Діє в розділах «Компанія» (Досьє, кадрові операції), «Бюджет»
--     (бюджети, HR-файли) і «Розвиток». Довідник співробітників і
--     оргструктуру бачать усі активні користувачі, як і раніше.
--  2. Чутливі дозволи — псевдорозділи в тих самих таблицях прав
--     (рівень 0 — ні, 1 — так):
--       pay     — зарплати й суми (hr_op_pay, HR-файли, HR-дошка)
--       docs    — особисті документи й нотатки в Досьє (і файли docs/…)
--       approve — проводити й скасовувати кадрові операції
--  3. Власник (app_users.is_owner) — один акаунт із повним доступом.
--     Його не можна вимкнути, видалити чи змінити йому роль. Роль
--     Адміністратора призначає й знімає лише Власник. Передати позначку
--     — app_transfer_owner(користувач), викликає сам Власник.
--  4. Ніхто, крім Власника й Адміністратора, не може видати іншим
--     (або взяти собі) більше прав, ніж має сам.
--  5. Шаблони ролей: HR, Рекрутер, Лінійний керівник; «Співробітник»
--     отримує новий шаблон, лише якщо його ще нікому не призначено.
--
--  Наявні ролі зберігають доступ: обсяг «вся компанія», pay — як було
--  з «Бюджетом» ≥ 1, docs — з «Компанією» ≥ 1, approve — з «Компанією» = 3.
--
--  Запускати ПІСЛЯ insert_access_tables.sql, secure_rls.sql,
--  employee_card.sql і hr_operations.sql — і повторно після кожного
--  з них, бо вони переписують політики своїх таблиць.
--  Скрипт можна запускати повторно. Відкат — rollback_roles_v2.sql.
-- ============================================================

do $$
begin
  if to_regprocedure('public.app_level(text)') is null then
    raise exception 'Спершу виконай insert_access_tables.sql (ролі та користувачі)';
  end if;
end $$;

-- ---------- Нові поля ----------
alter table app_role_perms add column if not exists scope text not null default 'all';
alter table app_role_perms drop constraint if exists app_role_perms_scope_chk;
alter table app_role_perms add constraint app_role_perms_scope_chk check (scope in ('own','unit','all'));

alter table app_users add column if not exists is_owner boolean not null default false;
create unique index if not exists app_users_one_owner on app_users ((true)) where is_owner;

-- ---------- Функції прав ----------
create or replace function app_is_owner() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from app_users where id = auth.uid() and is_owner and is_active);
$$;

-- Власник = повний доступ, як адміністратор
create or replace function app_is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from app_users u left join app_roles r on r.id = u.role_id
                  where u.id = auth.uid() and u.is_active and (u.is_owner or coalesce(r.is_admin, false)));
$$;

-- співробітник, прив'язаний до поточного користувача
create or replace function app_my_emp() returns bigint
language sql stable security definer set search_path = public as $$
  select employee_id::bigint from app_users where id = auth.uid() and is_active;
$$;

-- обсяг даних поточного користувача в розділі; без доступу до розділу — лише своє
create or replace function app_scope(p_section text) returns text
language sql stable security definer set search_path = public as $$
  select case
    when app_is_admin() then 'all'
    when app_level(p_section) < 1 then 'own'
    else coalesce((select rp.scope from app_users u join app_role_perms rp on rp.role_id = u.role_id
                    where u.id = auth.uid() and rp.section = p_section), 'all')
  end;
$$;

-- «мої підрозділи»: де я керівник + дочірні; якщо ніде не керівник — мій основний підрозділ + дочірні
create or replace function app_my_units() returns setof bigint
language sql stable security definer set search_path = public as $$
  with recursive me as (select app_my_emp() as emp),
  heads as (select c.id::bigint as id from company_units c, me where me.emp is not null and c.employee_id::bigint = me.emp),
  base as (
    select id from heads
    union
    select e.primary_unit_id::bigint from dict_employees e, me
     where e.id = me.emp and e.primary_unit_id is not null and not exists (select 1 from heads)
  ),
  tree as (
    select id from base
    union
    select c.id::bigint from company_units c join tree t on c.parent_id::bigint = t.id
  )
  select id from tree;
$$;

-- чи може поточний користувач бачити/змінювати запис про співробітника в розділі
create or replace function app_emp_ok(p_section text, p_emp bigint) returns boolean
language plpgsql stable security definer set search_path = public as $$
declare s text := app_scope(p_section); me bigint;
begin
  if s = 'all' then return true; end if;
  me := app_my_emp();
  if me is null or p_emp is null then return false; end if;
  if p_emp = me then return true; end if;
  if s = 'unit' then
    return exists (select 1 from dict_employees e
                    where e.id = p_emp and e.primary_unit_id::bigint in (select app_my_units()));
  end if;
  return false;
end $$;

-- чи може поточний користувач бачити/змінювати запис підрозділу в розділі
create or replace function app_unit_ok(p_section text, p_unit bigint) returns boolean
language plpgsql stable security definer set search_path = public as $$
declare s text := app_scope(p_section);
begin
  if s = 'all' then return true; end if;
  if s = 'unit' and p_unit is not null then
    return p_unit in (select app_my_units());
  end if;
  return false;
end $$;

-- чи можна поточному користувачу призначити роль (для панелі й функції admin-create-user)
create or replace function app_can_assign_role(p_role text) returns boolean
language sql stable security definer set search_path = public as $$
  select case
    when app_is_owner() then true
    when exists (select 1 from app_roles where id = p_role and is_admin) then false
    when app_is_admin() then true
    else not exists (select 1 from app_role_perms rp where rp.role_id = p_role and rp.level > app_level(rp.section))
  end;
$$;

revoke all on function app_my_emp(), app_scope(text), app_my_units(), app_emp_ok(text,bigint),
                       app_unit_ok(text,bigint), app_is_owner(), app_can_assign_role(text) from public, anon;
grant execute on function app_my_emp(), app_scope(text), app_my_units(), app_emp_ok(text,bigint),
                          app_unit_ok(text,bigint), app_is_owner(), app_can_assign_role(text) to authenticated;

-- ---------- Власник ----------
-- Перший активний адміністратор стає Власником, якщо Власника ще немає
update app_users set is_owner = true
 where id = (select u.id from app_users u join app_roles r on r.id = u.role_id
              where u.is_active and r.is_admin order by u.created_at, u.email limit 1)
   and not exists (select 1 from app_users where is_owner);

create or replace function app_users_owner_guard() returns trigger
language plpgsql security definer set search_path = public as $$
declare was_admin boolean; now_admin boolean;
begin
  if auth.uid() is null then                         -- SQL Editor / service_role
    return case when tg_op = 'DELETE' then old else new end;
  end if;
  if tg_op = 'DELETE' then
    if old.is_owner then raise exception 'Власника не можна видалити — спершу передай права власника'; end if;
    return old;
  end if;
  if tg_op = 'INSERT' then
    if new.is_owner then raise exception 'Власника призначає лише app_transfer_owner'; end if;
    if not app_can_assign_role(new.role_id) then
      raise exception 'Недостатньо прав, щоб призначити цю роль';
    end if;
    return new;
  end if;
  -- UPDATE
  if new.is_owner is distinct from old.is_owner and coalesce(current_setting('app.owner_transfer', true), '') <> 'on' then
    raise exception 'Права власника передаються лише кнопкою «Передати права власника»';
  end if;
  if old.is_owner and (new.is_active is distinct from old.is_active or new.role_id is distinct from old.role_id)
     and (auth.uid() <> old.id or not new.is_active) then
    raise exception 'Власника не можна вимкнути чи змінити йому роль';
  end if;
  if new.role_id is distinct from old.role_id then
    select coalesce(bool_or(is_admin), false) into was_admin from app_roles where id = old.role_id;
    select coalesce(bool_or(is_admin), false) into now_admin from app_roles where id = new.role_id;
    if (was_admin or now_admin) and not app_is_owner() then
      raise exception 'Призначати або знімати роль Адміністратора може лише Власник';
    end if;
    if not app_can_assign_role(new.role_id) then
      raise exception 'Недостатньо прав, щоб призначити цю роль';
    end if;
  end if;
  return new;
end $$;

drop trigger if exists app_users_owner_guard on app_users;
create trigger app_users_owner_guard before insert or update or delete on app_users
  for each row execute function app_users_owner_guard();

create or replace function app_transfer_owner(p_user uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not app_is_owner() then raise exception 'Передати права власника може лише Власник'; end if;
  if not exists (select 1 from app_users where id = p_user and is_active) then
    raise exception 'Новий власник має бути активним користувачем';
  end if;
  perform set_config('app.owner_transfer', 'on', true);
  update app_users set is_owner = false where is_owner and id <> p_user;
  update app_users set is_owner = true where id = p_user;
  perform set_config('app.owner_transfer', '', true);
end $$;
revoke all on function app_transfer_owner(uuid) from public, anon;
grant execute on function app_transfer_owner(uuid) to authenticated;

-- ролі з повним доступом змінює лише Власник
create or replace function app_roles_guard() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or app_is_owner() then
    return case when tg_op = 'DELETE' then old else new end;
  end if;
  if (tg_op = 'INSERT' and new.is_admin)
     or (tg_op = 'UPDATE' and new.is_admin is distinct from old.is_admin)
     or (tg_op = 'DELETE' and old.is_admin) then
    raise exception 'Роль із повним доступом змінює лише Власник';
  end if;
  return case when tg_op = 'DELETE' then old else new end;
end $$;
drop trigger if exists app_roles_guard on app_roles;
create trigger app_roles_guard before insert or update or delete on app_roles
  for each row execute function app_roles_guard();

-- не видавати більше прав, ніж маєш сам
create or replace function app_perms_guard() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or app_is_admin() then return new; end if;
  if new.level > app_level(new.section) then
    raise exception 'Не можна видати більше прав, ніж маєте самі (розділ %)', new.section;
  end if;
  return new;
end $$;
drop trigger if exists app_perms_guard on app_role_perms;
create trigger app_perms_guard before insert or update on app_role_perms
  for each row execute function app_perms_guard();
drop trigger if exists app_perms_guard on app_user_perms;
create trigger app_perms_guard before insert or update on app_user_perms
  for each row execute function app_perms_guard();

-- видалення користувача: Власника не можна
create or replace function app_delete_user(p_user uuid) returns void
language plpgsql security definer set search_path = public, auth as $$
begin
  if app_level('access') < 3 then
    raise exception 'Недостатньо прав для видалення користувачів';
  end if;
  if p_user = auth.uid() then
    raise exception 'Не можна видалити власний обліковий запис';
  end if;
  if exists (select 1 from app_users where id = p_user and is_owner) then
    raise exception 'Власника не можна видалити';
  end if;
  if exists (select 1 from app_users u join app_roles r on r.id = u.role_id where u.id = p_user and r.is_admin)
     and not app_is_owner() then
    raise exception 'Адміністратора може видалити лише Власник';
  end if;
  delete from auth.users where id = p_user;
end $$;

-- ---------- Чутливі дозволи для наявних ролей (зберегти теперішній доступ) ----------
insert into app_role_perms (role_id, section, level)
select r.id, f.section,
       case f.section
         when 'pay'     then case when coalesce((select level from app_role_perms where role_id = r.id and section = 'budget'), 0)  >= 1 then 1 else 0 end
         when 'docs'    then case when coalesce((select level from app_role_perms where role_id = r.id and section = 'company'), 0) >= 1 then 1 else 0 end
         when 'approve' then case when coalesce((select level from app_role_perms where role_id = r.id and section = 'company'), 0) >= 3 then 1 else 0 end
       end
  from app_roles r cross join (values ('pay'), ('docs'), ('approve')) f(section)
 where not r.is_admin
on conflict (role_id, section) do nothing;

-- індивідуальні винятки на «Бюджет»/«Компанію» → такі самі винятки на прапорці
insert into app_user_perms (user_id, section, level)
select user_id, 'pay', case when level >= 1 then 1 else 0 end from app_user_perms where section = 'budget'
on conflict (user_id, section) do nothing;
insert into app_user_perms (user_id, section, level)
select user_id, 'docs', case when level >= 1 then 1 else 0 end from app_user_perms where section = 'company'
on conflict (user_id, section) do nothing;
insert into app_user_perms (user_id, section, level)
select user_id, 'approve', case when level >= 3 then 1 else 0 end from app_user_perms where section = 'company'
on conflict (user_id, section) do nothing;

-- ---------- Шаблони ролей ----------
insert into app_roles (id, name, description, is_admin, is_system, sort) values
  ('hr',           'HR-менеджер',       'Персонал усієї компанії, досьє, зарплати, погодження кадрових операцій, розвиток і опитування', false, false, 4),
  ('recruiter',    'Рекрутер',          'Вакансії та кандидати; без зарплат і особистих документів співробітників',                        false, false, 5),
  ('line_manager', 'Лінійний керівник', 'Картки, розвиток і цілі своєї команди (свій підрозділ із дочірніми)',                             false, false, 6)
on conflict (id) do nothing;

-- розділ: рівень · обсяг для hr / recruiter / line_manager / employee
drop table if exists pg_temp._tpl;
create temp table _tpl (section text, hr int, hr_s text, rc int, rc_s text, lm int, lm_s text, em int, em_s text);
insert into _tpl values
  ('dash',      1,'all', 1,'all', 1,'all',  1,'all'),
  ('proc',      1,'all', 1,'all', 1,'all',  1,'all'),
  ('matrix',    1,'all', 1,'all', 1,'all',  1,'all'),
  ('goals',     2,'all', 0,'all', 2,'all',  1,'all'),
  ('company',   3,'all', 1,'own', 1,'unit', 1,'own'),
  ('reports',   1,'all', 0,'all', 1,'all',  0,'all'),
  ('analytics', 1,'all', 0,'all', 0,'all',  0,'all'),
  ('budget',    1,'all', 0,'all', 1,'unit', 0,'all'),
  ('dev',       3,'all', 0,'all', 2,'unit', 1,'own'),
  ('bot',       2,'all', 2,'all', 1,'all',  0,'all'),
  ('settings',  0,'all', 0,'all', 0,'all',  0,'all'),
  ('access',    0,'all', 0,'all', 0,'all',  0,'all'),
  ('pay',       1,'all', 0,'all', 0,'all',  0,'all'),
  ('docs',      1,'all', 0,'all', 0,'all',  0,'all'),
  ('approve',   1,'all', 0,'all', 1,'all',  0,'all');

-- нові ролі: заповнити, лише якщо їм ще нікого не призначено (інакше не чіпати чужі правки)
insert into app_role_perms (role_id, section, level, scope)
select x.role_id, t.section, x.lv, x.sc
  from _tpl t
 cross join lateral (values ('hr', t.hr, t.hr_s), ('recruiter', t.rc, t.rc_s), ('line_manager', t.lm, t.lm_s)) x(role_id, lv, sc)
on conflict (role_id, section) do nothing;

do $$
begin
  if exists (select 1 from app_roles where id = 'employee')
     and not exists (select 1 from app_users where role_id = 'employee') then
    insert into app_role_perms (role_id, section, level, scope)
    select 'employee', section, em, em_s from _tpl
    on conflict (role_id, section) do update set level = excluded.level, scope = excluded.scope;
    update app_roles set description = 'Самообслуговування: свій профіль і розвиток, структура компанії, процеси' where id = 'employee';
  else
    raise notice 'Роль «Співробітник» уже призначена користувачам — її права не змінено. Шаблон можна застосувати вручну в панелі.';
  end if;
end $$;

-- ---------- Політики таблиць з обсягом ----------
create or replace function pg_temp.has_cols(p_table text, p_cols text[]) returns boolean
language sql as $$
  select to_regclass('public.' || p_table) is not null
     and (select count(*) from information_schema.columns
           where table_schema = 'public' and table_name = p_table and column_name = any(p_cols)) = cardinality(p_cols);
$$;

-- p_cond — умова обсягу на рядок; p_flag — потрібний прапорець; p_dash — читає й «Панель»
create or replace function pg_temp.scoped(p_table text, p_section text, p_cols text[], p_cond text,
                                          p_flag text default null, p_dash boolean default false,
                                          p_del_extra text default null)
returns void language plpgsql as $$
declare pol record; rd text; ed text; dl text; fl text := 'true';
begin
  if not pg_temp.has_cols(p_table, p_cols) then
    raise notice 'Таблиці % (або полів %) немає — пропускаю', p_table, p_cols;
    return;
  end if;
  for pol in select policyname from pg_policies where schemaname = 'public' and tablename = p_table loop
    execute format('drop policy %I on public.%I', pol.policyname, p_table);
  end loop;
  execute format('alter table public.%I enable row level security', p_table);
  if p_flag is not null then fl := format('app_level(%L) >= 1', p_flag); end if;

  rd := format('app_level(%L) >= 1', p_section);
  if p_dash then rd := format('(%s or app_level(''dash'') >= 1)', rd); end if;
  rd := format('%s and %s and (%s)', rd, fl, p_cond);
  ed := format('app_level(%L) >= 2 and %s and (%s)', p_section, fl, p_cond);
  dl := format('app_level(%L) >= 3 and %s and (%s)', p_section, fl, p_cond);
  if p_del_extra is not null then dl := dl || ' and ' || p_del_extra; end if;

  execute format('create policy "read" on public.%I for select to authenticated using (%s)', p_table, rd);
  execute format('create policy "write" on public.%I for insert to authenticated with check (%s)', p_table, ed);
  execute format('create policy "update" on public.%I for update to authenticated using (%s) with check (%s)', p_table, ed, ed);
  execute format('create policy "remove" on public.%I for delete to authenticated using (%s)', p_table, dl);
end $$;

-- Досьє
select pg_temp.scoped('emp_notes',     'company', array['employee_id'], 'app_emp_ok(''company'', employee_id)', 'docs');
select pg_temp.scoped('emp_documents', 'company', array['employee_id'], 'app_emp_ok(''company'', employee_id)', 'docs');
select pg_temp.scoped('emp_trainings', 'company', array['employee_id'], 'app_emp_ok(''company'', employee_id)');
select pg_temp.scoped('emp_vacations', 'company', array['employee_id'], 'app_emp_ok(''company'', employee_id)');

-- Кадрові операції (видалити можна лише чернетку або операцію на погодженні)
select pg_temp.scoped('hr_operations', 'company', array['employee_id'], 'app_emp_ok(''company'', employee_id)',
                      null, false, 'status in (''draft'',''pending'')');
select pg_temp.scoped('hr_op_pay', 'company', array['op_id'],
                      'exists (select 1 from hr_operations o where o.id = op_id and app_emp_ok(''company'', o.employee_id))', 'pay');
-- читати суми можна й з рівнем «Перегляд»; змінювати — з «Редагуванням» у «Компанії»
do $$
begin
  if to_regclass('public.hr_op_pay') is not null then
    drop policy if exists "remove" on hr_op_pay;
    create policy "remove" on hr_op_pay for delete to authenticated using (
      app_level('company') >= 2 and app_level('pay') >= 1
      and exists (select 1 from hr_operations o where o.id = op_id and app_emp_ok('company', o.employee_id)));
  end if;
end $$;

-- Бюджет, HR-файли, HR-дошка
select pg_temp.scoped('budgets',        'budget', array['unit_id'], 'app_unit_ok(''budget'', unit_id)');
select pg_temp.scoped('budget_entries', 'budget', array['unit_id'], 'app_unit_ok(''budget'', unit_id)');
select pg_temp.scoped('hr_files',       'budget', array['unit_id'], 'app_unit_ok(''budget'', unit_id)', 'pay');
select pg_temp.scoped('hr_entries',     'budget', array['unit_id','employee_id'],
                      'app_unit_ok(''budget'', unit_id) or app_emp_ok(''budget'', employee_id)', 'pay');

-- Розвиток (панель теж читає, але в межах обсягу «Розвитку»)
select pg_temp.scoped('dev_plans',    'dev', array['employee_id'], 'app_emp_ok(''dev'', employee_id)', null, true);
select pg_temp.scoped('dev_sessions', 'dev', array['plan_id'],
                      'exists (select 1 from dev_plans p where p.id = plan_id and app_emp_ok(''dev'', p.employee_id))', null, true);
select pg_temp.scoped('dev_swot',     'dev', array['plan_id'],
                      'exists (select 1 from dev_plans p where p.id = plan_id and app_emp_ok(''dev'', p.employee_id))', null, true);

-- Файли Досьє: фото — за «Компанією», документи docs/<id співробітника>/… — ще й з прапорцем docs і обсягом
do $$
declare cond text;
begin
  if to_regclass('storage.objects') is null or not exists (select 1 from storage.buckets where id = 'emp-files') then
    raise notice 'Сховища emp-files немає — пропускаю';
    return;
  end if;
  cond := '(name not like ''docs/%%'' or (app_level(''docs'') >= 1 and split_part(name, ''/'', 2) ~ ''^[0-9]+$'' and app_emp_ok(''company'', split_part(name, ''/'', 2)::bigint)))';
  drop policy if exists "emp-files read"   on storage.objects;
  drop policy if exists "emp-files insert" on storage.objects;
  drop policy if exists "emp-files update" on storage.objects;
  drop policy if exists "emp-files delete" on storage.objects;
  execute format('create policy "emp-files read" on storage.objects for select to authenticated using (bucket_id = ''emp-files'' and app_level(''company'') >= 1 and %s)', cond);
  execute format('create policy "emp-files insert" on storage.objects for insert to authenticated with check (bucket_id = ''emp-files'' and app_level(''company'') >= 2 and %s)', cond);
  execute format('create policy "emp-files update" on storage.objects for update to authenticated using (bucket_id = ''emp-files'' and app_level(''company'') >= 2 and %s)', cond);
  execute format('create policy "emp-files delete" on storage.objects for delete to authenticated using (bucket_id = ''emp-files'' and app_level(''company'') >= 2 and %s)', cond);
end $$;

-- Провести або скасувати кадрову операцію: прапорець «Погодження», «Компанія» ≥ 2 і людина в межах обсягу
do $$
begin
  if to_regclass('public.hr_operations') is null then return; end if;
  create or replace function hr_operations_guard() returns trigger
  language plpgsql as $f$
  begin
    if to_regprocedure('public.app_level(text)') is null or auth.uid() is null then
      return new;                                         -- без системи прав або service_role (бот)
    end if;
    if new.status is distinct from old.status and new.status in ('posted','cancelled')
       and not (app_level('approve') >= 1 and app_level('company') >= 2 and app_emp_ok('company', new.employee_id)) then
      raise exception 'Провести або скасувати операцію може лише користувач із дозволом «Погодження»';
    end if;
    if old.status = 'posted' and new.status not in ('posted','cancelled') then
      raise exception 'Проведену операцію не можна повернути в чернетку — скасуй її';
    end if;
    if old.status in ('posted','cancelled') and (new.kind, new.employee_id, new.effective_date, new.after)
         is distinct from (old.kind, old.employee_id, old.effective_date, old.after) then
      raise exception 'Проведену або скасовану операцію змінювати не можна — створи нову';
    end if;
    return new;
  end $f$;
end $$;

-- Перевірка
select (select email from app_users where is_owner)                                as owner,
       (select count(*) from app_roles)                                            as roles,
       (select count(*) from app_role_perms where section in ('pay','docs','approve')) as flag_rows,
       (select count(*) from pg_policies where policyname = 'read'
          and (qual like '%app_emp_ok%' or qual like '%app_unit_ok%'))             as scoped_tables;
