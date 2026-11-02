-- ============================================================
--  Довідник співробітників: кадрові поля для Telegram-бота
--  (крок 1 плану за ТЗ: «Мій профіль», стаж, дні народження)
--  Можна запускати повторно.
-- ============================================================

alter table dict_employees add column if not exists position       text;  -- актуальна посада
alter table dict_employees add column if not exists hire_date      date;  -- дата прийому (стаж рахується від неї)
alter table dict_employees add column if not exists dismissal_date date;  -- дата звільнення (порожньо = працює)

alter table dict_employees drop constraint if exists dict_employees_dates_chk;
alter table dict_employees add constraint dict_employees_dates_chk
  check (dismissal_date is null or hire_date is null or dismissal_date >= hire_date);

-- Дні народження шукаються за місяцем і днем
create index if not exists dict_employees_birth_md_idx
  on dict_employees ((extract(month from birthdate)), (extract(day from birthdate)))
  where birthdate is not null;

-- Перевірка
select count(*) as employees,
       count(birthdate) as with_birthdate,
       count(hire_date) as with_hire_date,
       count(position)  as with_position,
       count(phone)     as with_phone
from dict_employees;
