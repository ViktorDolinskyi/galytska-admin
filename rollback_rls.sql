-- Відкат secure_rls.sql: повертає робочі таблиці до режиму
-- «будь-який залогінений користувач може все» (без входу — як і раніше, нічого).
-- Використовувати лише якщо після secure_rls.sql щось перестало працювати.
do $$
declare t text; pol record;
begin
  foreach t in array array[
    'company_units','dict_unit_types','dict_unit_kinds','dict_employees',
    'matrix_rows','matrix_configs','goals','goal_indicators','goal_types','goal_patterns',
    'dev_plans','dev_sessions','dev_swot','dict_survey_types',
    'budgets','budget_categories','budget_expense_items','budget_entries','hr_files','hr_entries',
    'bot_users','bot_news','bot_faq','bot_contacts','bot_documents'] loop
    if to_regclass('public.' || t) is null then continue; end if;
    for pol in select policyname from pg_policies where schemaname = 'public' and tablename = t loop
      execute format('drop policy %I on public.%I', pol.policyname, t);
    end loop;
    execute format('alter table public.%I enable row level security', t);
    execute format('create policy "authenticated full access" on public.%I for all to authenticated using (true) with check (true)', t);
  end loop;
end $$;
