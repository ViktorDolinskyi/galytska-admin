// Edge Function: створення користувача Admin GS адміністратором.
//
// Публічна реєстрація в Supabase вимкнена (Authentication → Sign In / Providers → Allow new users to sign up = off),
// тому нових користувачів створює лише ця функція — на сервері, з ключем service_role,
// і лише для того, у кого в панелі право «Користувачі та доступ» ≥ Редагування.
//
// Тіло запиту (JSON): { email, password?, full_name?, role_id, employee_id?, is_active?, redirect_to? }
//   password задано  → обліковий запис одразу активний з цим паролем;
//   password порожній → користувачу йде лист-запрошення, пароль він задає сам.
import { createClient } from "npm:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "Метод не підтримується" }, 405);

  const url = Deno.env.get("SUPABASE_URL")!;
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

  // 1. Хто викликає і чи має право (перевіряє сама база: app_level враховує роль, винятки й is_active)
  const caller = createClient(url, anonKey, {
    global: { headers: { Authorization: req.headers.get("Authorization") ?? "" } },
    auth: { persistSession: false },
  });
  const { data: level, error: levelErr } = await caller.rpc("app_level", { p_section: "access" });
  if (levelErr) return json({ error: "Не вдалося перевірити права: " + levelErr.message }, 401);
  if ((level ?? 0) < 2) return json({ error: "Недостатньо прав для створення користувачів" }, 403);

  // 2. Дані
  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return json({ error: "Некоректний запит" }, 400); }
  const email = String(body.email ?? "").trim().toLowerCase();
  const password = String(body.password ?? "");
  const full_name = (String(body.full_name ?? "").trim()) || null;
  const role_id = String(body.role_id ?? "");
  const employee_id = body.employee_id ?? null;
  const is_active = body.is_active !== false;
  if (!/^\S+@\S+\.\S+$/.test(email)) return json({ error: "Вкажіть коректний email" }, 400);
  if (password && password.length < 8) return json({ error: "Пароль має містити щонайменше 8 символів" }, 400);
  if (!role_id) return json({ error: "Оберіть роль" }, 400);

  const admin = createClient(url, serviceKey, { auth: { persistSession: false } });
  const { data: role } = await admin.from("app_roles").select("id").eq("id", role_id).maybeSingle();
  if (!role) return json({ error: "Такої ролі немає" }, 400);

  // 3. Обліковий запис Supabase Auth (тригер у базі одразу створює рядок app_users)
  const res = password
    ? await admin.auth.admin.createUser({ email, password, email_confirm: true, user_metadata: { full_name } })
    : await admin.auth.admin.inviteUserByEmail(email, {
        data: { full_name },
        redirectTo: typeof body.redirect_to === "string" ? body.redirect_to : undefined,
      });
  if (res.error) {
    const exists = /already|registered|exists/i.test(res.error.message);
    return json({ error: exists ? "Користувач з таким email уже існує" : res.error.message }, exists ? 409 : 400);
  }
  const id = res.data.user!.id;

  // 4. Профіль у панелі: роль, співробітник, стан
  const { error: upErr } = await admin.from("app_users")
    .upsert({ id, email, full_name, role_id, employee_id, is_active });
  if (upErr) return json({ error: "Обліковий запис створено, але не вдалося зберегти роль: " + upErr.message, id }, 500);

  return json({ id, invited: !password });
});
