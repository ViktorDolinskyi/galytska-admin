-- ============================================================
--  Відкат roles_v2.sql: повертає права, як були до нього
--  (рівні 0–3 по розділах без обсягу, прапорців і Власника).
--  Нові ролі, колонки scope / is_owner і рядки прапорців лишаються
--  в базі, але ні на що не впливають. Можна запускати повторно.
-- ============================================================

drop trigger if exists app_users_owner_guard on app_users;
drop trigger if exists app_roles_guard on app_roles;
drop trigger if exists app_perms_guard on app_role_perms;
drop trigger if exists app_perms_guard on app_user_perms;

create or replace function app_is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from app_users u join app_roles r on r.id = u.role_id
                  where u.id = auth.uid() and u.is_active and r.is_admin);
$$;

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

-- політики, як у secure_rls.sql / employee_card.sql / hr_operations.sql
create or replace function pg_temp.plain(p_table text, rd text, ed text, dl text) returns void
language plpgsql as $$
declare pol record;
begin
  if to_regclass('public.' || p_table) is null then return; end if;
  for pol in select policyname from pg_policies where schemaname = 'public' and tablename = p_table loop
    execute format('drop policy %I on public.%I', pol.policyname, p_table);
  end loop;
  execute format('create policy "read" on public.%I for select to authenticated using (%s)', p_table, rd);
  execute format('create policy "write" on public.%I for insert to authenticated with check (%s)', p_table, ed);
  execute format('create policy "update" on public.%I for update to authenticated using (%s) with check (%s)', p_table, ed, ed);
  execute format('create policy "remove" on public.%I for delete to authenticated using (%s)', p_table, dl);
end $$;

select pg_temp.plain(t, 'app_level(''company'') >= 1', 'app_level(''company'') >= 2', 'app_level(''company'') >= 3')
  from unnest(array['emp_notes','emp_documents','emp_trainings','emp_vacations']) t;
select pg_temp.plain('hr_operations', 'app_level(''company'') >= 1', 'app_level(''company'') >= 2',
                     'app_level(''company'') >= 3 and status in (''draft'',''pending'')');
select pg_temp.plain('hr_op_pay', 'app_level(''budget'') >= 1', 'app_level(''budget'') >= 1 and app_level(''company'') >= 2',
                     'app_level(''budget'') >= 1 and app_level(''company'') >= 2');
select pg_temp.plain(t, 'app_level(''budget'') >= 1', 'app_level(''budget'') >= 2', 'app_level(''budget'') >= 3')
  from unnest(array['budgets','budget_entries','hr_files','hr_entries']) t;
select pg_temp.plain(t, 'app_level(''dev'') >= 1 or app_level(''dash'') >= 1', 'app_level(''dev'') >= 2', 'app_level(''dev'') >= 3')
  from unnest(array['dev_plans','dev_sessions','dev_swot']) t;

do $$
begin
  if to_regclass('storage.objects') is null then return; end if;
  drop policy if exists "emp-files read"   on storage.objects;
  drop policy if exists "emp-files insert" on storage.objects;
  drop policy if exists "emp-files update" on storage.objects;
  drop policy if exists "emp-files delete" on storage.objects;
  create policy "emp-files read" on storage.objects for select to authenticated using (bucket_id = 'emp-files' and app_level('company') >= 1);
  create policy "emp-files insert" on storage.objects for insert to authenticated with check (bucket_id = 'emp-files' and app_level('company') >= 2);
  create policy "emp-files update" on storage.objects for update to authenticated using (bucket_id = 'emp-files' and app_level('company') >= 2);
  create policy "emp-files delete" on storage.objects for delete to authenticated using (bucket_id = 'emp-files' and app_level('company') >= 2);
end $$;

do $$
begin
  if to_regclass('public.hr_operations') is null then return; end if;
  create or replace function hr_operations_guard() returns trigger
  language plpgsql as $f$
  begin
    if to_regprocedure('public.app_level(text)') is null or auth.uid() is null then
      return new;
    end if;
    if new.status is distinct from old.status and new.status in ('posted','cancelled')
       and app_level('company') < 3 then
      raise exception 'Провести або скасувати операцію може лише користувач з повним доступом до розділу «Компанія»';
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

select 'roles_v2 відкочено' as result;
