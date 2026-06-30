-- ============================================================
--  HR-board: структура таблиць
--  Співробітники беруться з dict_employees (розділ Компанія)
-- ============================================================

-- 1. HR-файли (один файл = підрозділ + рік)
create table if not exists hr_files (
  id         uuid not null default gen_random_uuid() primary key,
  unit_id    int  not null,
  year       int  not null,
  status     text not null default 'draft',  -- draft | approved
  note       text,
  created_at timestamptz not null default now(),
  unique(unit_id, year)
);

-- 2. Записи ФОП (employee_id → dict_employees.id)
create table if not exists hr_entries (
  id            uuid   not null default gen_random_uuid() primary key,
  hr_file_id    uuid   not null references hr_files(id) on delete cascade,
  employee_id   bigint not null,   -- dict_employees.id
  unit_id       int    not null,
  year          int    not null,
  month         int    not null check (month between 1 and 12),
  amount_plan   numeric(14,2) not null default 0,
  amount_fact   numeric(14,2) not null default 0,
  unique(employee_id, month, year, unit_id)
);

-- Індекси
create index if not exists hr_entries_year_idx     on hr_entries(year);
create index if not exists hr_entries_unit_idx     on hr_entries(unit_id);
create index if not exists hr_entries_employee_idx on hr_entries(employee_id);
create index if not exists hr_files_unit_idx       on hr_files(unit_id);

-- RLS
alter table hr_files   enable row level security;
alter table hr_entries enable row level security;

create policy "allow all hr_files"   on hr_files   for all using (true) with check (true);
create policy "allow all hr_entries" on hr_entries for all using (true) with check (true);
