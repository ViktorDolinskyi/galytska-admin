-- ============================================================
--  HR-файл: одна людина може мати кілька посад у підрозділі
--  (підвищення, переведення в середині року).
--  Кожен рядок HR-файлу отримує номер row_no; унікальність
--  тепер: файл + рядок + місяць, а не людина + місяць.
--  Скрипт можна запускати повторно.
-- ============================================================

-- 1. Номер рядка в HR-файлі
alter table hr_entries add column if not exists row_no int;

-- 2. Заповнити row_no для існуючих записів (один рядок на людину, як було)
update hr_entries e
set row_no = r.rn
from (
  select hr_file_id, employee_id,
         dense_rank() over (partition by hr_file_id order by employee_id) - 1 as rn
  from hr_entries
  group by hr_file_id, employee_id
) r
where e.hr_file_id = r.hr_file_id
  and e.employee_id = r.employee_id
  and e.row_no is null;

-- 3. Прибрати старе обмеження «людина + місяць + рік + підрозділ»
do $$
declare c record;
begin
  for c in
    select conname from pg_constraint
    where conrelid = 'hr_entries'::regclass and contype = 'u'
      and conname <> 'hr_entries_file_row_month_key'
  loop
    execute format('alter table hr_entries drop constraint %I', c.conname);
  end loop;
end $$;

-- 4. Нове обмеження: файл + рядок + місяць
do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'hr_entries_file_row_month_key') then
    alter table hr_entries add constraint hr_entries_file_row_month_key unique (hr_file_id, row_no, month);
  end if;
end $$;
