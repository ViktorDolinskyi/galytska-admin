-- ============================================================
--  Права доступу на рівні бази (RLS)
--
--  Прив'язує кожну робочу таблицю до розділу адмінки й перевіряє
--  рівень доступу поточного користувача через app_level('розділ'):
--    читання     — рівень ≥ 1 (Перегляд)
--    додавання і
--    зміна       — рівень ≥ 2 (Редагування)
--    видалення   — рівень ≥ 3 (Повний)
--  Довідники (співробітники, оргструктура) читає будь-який активний
--  користувач, бо вони потрібні в багатьох розділах.
--  Без входу в систему (anon) доступу немає ні до чого.
--  Telegram-бот працює з ключем service_role, тому його це не зачіпає.
--
--  Спершу має бути виконаний insert_access_tables.sql.
--  Скрипт можна запускати повторно. Відкат — rollback_rls.sql.
-- ============================================================

do $$
begin
  if to_regprocedure('public.app_level(text)') is null then
    raise exception 'Спершу виконай insert_access_tables.sql (ролі та користувачі)';
  end if;
  if not exists (select 1 from app_users u join app_roles r on r.id = u.role_id
                  where u.is_active and r.is_admin) then
    raise exception 'Немає жодного активного адміністратора — інакше всі втратять доступ';
  end if;
end $$;

-- активний користувач панелі (будь-яка роль)
create or replace function app_is_active() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from app_users where id = auth.uid() and is_active);
$$;

-- таблиця → розділ; dash = таблицю також читає «Панель керування»
create or replace function pg_temp.secure(p_table text, p_section text, p_dash boolean default false)
returns void language plpgsql as $$
declare pol record; rd text;
begin
  if to_regclass('public.' || p_table) is null then
    raise notice 'Таблиці % немає — пропускаю', p_table;
    return;
  end if;
  for pol in select policyname from pg_policies where schemaname = 'public' and tablename = p_table loop
    execute format('drop policy %I on public.%I', pol.policyname, p_table);
  end loop;
  execute format('alter table public.%I enable row level security', p_table);

  rd := format('app_level(%L) >= 1', p_section);
  if p_dash then rd := rd || ' or app_level(''dash'') >= 1'; end if;

  execute format('create policy "read" on public.%I for select to authenticated using (%s)', p_table, rd);
  execute format('create policy "write" on public.%I for insert to authenticated with check (app_level(%L) >= 2)', p_table, p_section);
  execute format('create policy "update" on public.%I for update to authenticated using (app_level(%L) >= 2) with check (app_level(%L) >= 2)', p_table, p_section, p_section);
  execute format('create policy "remove" on public.%I for delete to authenticated using (app_level(%L) >= 3)', p_table, p_section);
end $$;

-- довідники: читає будь-який активний користувач, змінює «Компанія»
create or replace function pg_temp.secure_dict(p_table text, p_extra_edit text default null)
returns void language plpgsql as $$
declare pol record; ed text;
begin
  if to_regclass('public.' || p_table) is null then
    raise notice 'Таблиці % немає — пропускаю', p_table;
    return;
  end if;
  for pol in select policyname from pg_policies where schemaname = 'public' and tablename = p_table loop
    execute format('drop policy %I on public.%I', pol.policyname, p_table);
  end loop;
  execute format('alter table public.%I enable row level security', p_table);

  ed := 'app_level(''company'') >= 2';
  if p_extra_edit is not null then ed := ed || format(' or app_level(%L) >= 2', p_extra_edit); end if;

  execute format('create policy "read" on public.%I for select to authenticated using (app_is_active())', p_table);
  execute format('create policy "write" on public.%I for insert to authenticated with check (app_level(''company'') >= 2)', p_table);
  execute format('create policy "update" on public.%I for update to authenticated using (%s) with check (%s)', p_table, ed, ed);
  execute format('create policy "remove" on public.%I for delete to authenticated using (app_level(''company'') >= 3)', p_table);
end $$;

-- Довідники
select pg_temp.secure_dict('company_units');
select pg_temp.secure_dict('dict_unit_types');
select pg_temp.secure_dict('dict_unit_kinds');
select pg_temp.secure_dict('dict_employees', 'bot');   -- телефон і доступ до бота змінюють і з «Будь в темі»

-- Матриці
select pg_temp.secure('matrix_rows',    'matrix');
select pg_temp.secure('matrix_configs', 'matrix');

-- Цілі
select pg_temp.secure('goals',           'goals', true);
select pg_temp.secure('goal_indicators', 'goals', true);
select pg_temp.secure('goal_types',      'goals');
select pg_temp.secure('goal_patterns',   'goals');

-- Розвиток
select pg_temp.secure('dev_plans',         'dev', true);
select pg_temp.secure('dev_sessions',      'dev', true);
select pg_temp.secure('dev_swot',          'dev', true);
select pg_temp.secure('dict_survey_types', 'dev');

-- Бюджет і HR-board
select pg_temp.secure('budgets',              'budget');
select pg_temp.secure('budget_categories',    'budget');
select pg_temp.secure('budget_expense_items', 'budget');
select pg_temp.secure('budget_entries',       'budget');
select pg_temp.secure('hr_files',             'budget');
select pg_temp.secure('hr_entries',           'budget');

-- Будь в темі (Telegram-бот)
select pg_temp.secure('bot_users',     'bot');
select pg_temp.secure('bot_news',      'bot');
select pg_temp.secure('bot_faq',       'bot');
select pg_temp.secure('bot_contacts',  'bot');
select pg_temp.secure('bot_documents', 'bot');
