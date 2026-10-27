// Створення користувача Admin GS адміністратором.
// Самореєстрацію в Supabase вимкнено, тож панель створює людей через цю функцію:
// вона перевіряє, що виклик зробив активний користувач із правом «Користувачі та доступ»
// не нижче «Редагування» (app_level('access') >= 2), і лише тоді викликає admin API.
// Службовий ключ доступний лише тут, у змінних середовища Supabase.
import { createClient } from 'npm:@supabase/supabase-js@2';

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, 'Content-Type': 'application/json' } });

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  if (req.method !== 'POST') return json({ error: 'Лише POST' }, 405);

  const url = Deno.env.get('SUPABASE_URL')!;
  const anonKey = Deno.env.get('SUPABASE_ANON_KEY')!;
  const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

  // хто викликає: клієнт із токеном користувача, тож app_level бачить його auth.uid()
  const authHeader = req.headers.get('Authorization') ?? '';
  if (!authHeader.startsWith('Bearer ')) return json({ error: 'Потрібен вхід у систему' }, 401);
  const caller = createClient(url, anonKey, {
    global: { headers: { Authorization: authHeader } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: who } = await caller.auth.getUser();
  if (!who?.user) return json({ error: 'Сесія недійсна, увійдіть знову' }, 401);
  const { data: level, error: levelError } = await caller.rpc('app_level', { p_section: 'access' });
  if (levelError) return json({ error: 'Не вдалося перевірити права: ' + levelError.message }, 500);
  if (typeof level !== 'number' || level < 2) return json({ error: 'Недостатньо прав для створення користувачів' }, 403);

  let body: { email?: unknown; password?: unknown; full_name?: unknown };
  try { body = await req.json(); } catch { return json({ error: 'Некоректний запит' }, 400); }
  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  const fullName = typeof body.full_name === 'string' && body.full_name.trim() ? body.full_name.trim().slice(0, 200) : null;
  if (!/^\S+@\S+\.\S+$/.test(email) || email.length > 254) return json({ error: 'Вкажіть коректний email' }, 400);
  if (password.length < 8 || password.length > 72) return json({ error: 'Пароль має містити від 8 до 72 символів' }, 400);

  const admin = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data, error } = await admin.auth.admin.createUser({
    email,
    password,
    email_confirm: true, // адмін створює акаунт сам, лист-підтвердження не потрібен
    user_metadata: fullName ? { full_name: fullName } : {},
  });
  if (error) {
    const exists = /already|registered|exists/i.test(error.message);
    return json({ error: exists ? 'Користувач з таким email уже існує' : error.message }, exists ? 409 : 400);
  }
  return json({ id: data.user.id });
});
