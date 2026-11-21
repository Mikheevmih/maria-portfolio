/**
 * Secure admin API for maria-portfolio on GitHub Pages.
 *
 * Public configuration is in wrangler.toml and admin/config.json.
 * NEVER put passwords, session keys or GitHub tokens in this repository.
 * Required encrypted Cloudflare secrets:
 *   ADMIN_PASSWORD
 *   SESSION_SECRET
 *   GITHUB_TOKEN
 */
const enc = new TextEncoder();
const dec = new TextDecoder();
const FILE_URL = "https://api.github.com/repos/";
const SESSION_DURATION_SECONDS = 8 * 60 * 60;

function response(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers }
  });
}
function error(message, status = 400) { return response({ error: message }, status); }
function b64url(bytes) {
  let result = "";
  for (let i = 0; i < bytes.length; i += 8192)
    result += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(result).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromB64url(text) {
  const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - text.length % 4) % 4));
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}
async function hmacKey(secret) {
  return crypto.subtle.importKey("raw", enc.encode(secret), { name:"HMAC", hash:"SHA-256" }, false, ["sign","verify"]);
}
async function createSession(env) {
  const payload = b64url(enc.encode(JSON.stringify({
    user: env.ADMIN_USERNAME,
    exp: Math.floor(Date.now() / 1000) + SESSION_DURATION_SECONDS
  })));
  const signature = b64url(new Uint8Array(await crypto.subtle.sign("HMAC", await hmacKey(env.SESSION_SECRET), enc.encode(payload))));
  return payload + "." + signature;
}
async function verifySession(request, env) {
  const bearer = request.headers.get("Authorization") || "";
  if (!bearer.startsWith("Bearer ")) return false;
  const [payload, sig, extra] = bearer.slice(7).split(".");
  if (!payload || !sig || extra) return false;
  try {
    const valid = await crypto.subtle.verify("HMAC", await hmacKey(env.SESSION_SECRET), fromB64url(sig), enc.encode(payload));
    if (!valid) return false;
    const data = JSON.parse(dec.decode(fromB64url(payload)));
    return data.user === env.ADMIN_USERNAME && Number.isSafeInteger(data.exp) && data.exp > Date.now()/1000;
  } catch { return false; }
}
async function equalPasswords(given, stored) {
  const [x, y] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(given)),
    crypto.subtle.digest("SHA-256", enc.encode(stored))
  ]);
  const a = new Uint8Array(x), b = new Uint8Array(y);
  let mismatch = 0;
  for (let i=0; i<a.length; i++) mismatch |= a[i] ^ b[i];
  return mismatch === 0;
}
async function parseJson(request, maxBytes) {
  const contentLength = Number(request.headers.get("Content-Length") || 0);
  if (contentLength > maxBytes) throw new Error("Слишком большой запрос.");
  const text = await request.text();
  if (enc.encode(text).length > maxBytes) throw new Error("Слишком большой запрос.");
  return JSON.parse(text);
}
async function github(env, method, path, body) {
  const url = FILE_URL + encodeURIComponent(env.GITHUB_REPO.split("/")[0]) + "/" + encodeURIComponent(env.GITHUB_REPO.split("/")[1]) + "/contents/" + path + "?ref=" + encodeURIComponent(env.GITHUB_BRANCH || "main");
  const result = await fetch(url, {
    method,
    headers: {
      "Authorization": "Bearer " + env.GITHUB_TOKEN,
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json",
      "User-Agent": "maria-portfolio-admin"
    },
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await result.json().catch(() => ({}));
  if (!result.ok) {
    if (result.status === 409 || result.status === 422) throw {status:409, message:"Файл изменился в GitHub. Перезагрузи данные и повтори сохранение."};
    if (result.status === 401 || result.status === 403) throw {status:502, message:"Нет доступа к GitHub. Проверь секрет GITHUB_TOKEN и права Contents: Read and write."};
    throw {status:502, message:"GitHub вернул ошибку (" + result.status + ")."};
  }
  return data;
}
function gitFileText(data) {
  if (!data || !data.content || data.encoding !== "base64") throw {status:502, message:"GitHub не вернул файл."};
  const binary = atob(data.content.replace(/\s+/g, ""));
  return dec.decode(Uint8Array.from(binary, c => c.charCodeAt(0)));
}
function base64FromUtf8(text) {
  const bytes = enc.encode(text);
  let binary = "";
  for (let i=0; i<bytes.length; i+=8192) binary += String.fromCharCode(...bytes.subarray(i,i+8192));
  return btoa(binary);
}
async function route(request, env) {
  const url = new URL(request.url);
  if (url.pathname === "/health" && request.method === "GET") return response({ok:true});
  if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET || !env.GITHUB_TOKEN ||
      !env.ADMIN_USERNAME || !env.GITHUB_REPO || !env.SITE_ORIGIN)
    return error("API ещё не настроен: добавь секреты и параметры Worker.", 503);

  if (url.pathname === "/login" && request.method === "POST") {
    const data = await parseJson(request, 4096);
    const username = String(data.username || "").trim();
    const password = String(data.password || "");
    if (username.length > 200 || password.length > 1024) return error("Неверный логин или пароль.", 401);
    const valid = await equalPasswords(password, env.ADMIN_PASSWORD);
    if (username !== env.ADMIN_USERNAME || !valid) return error("Неверный логин или пароль.", 401);
    return response({ token:await createSession(env), expiresIn: SESSION_DURATION_SECONDS });
  }

  if (!(await verifySession(request, env))) return error("Сессия истекла. Войди снова.", 401);

  if (url.pathname === "/site" && request.method === "GET") {
    const item = await github(env, "GET", "index.html", null);
    return response({ html:gitFileText(item), sha:item.sha });
  }
  if (url.pathname === "/site" && request.method === "PUT") {
    const data = await parseJson(request, 800000);
    if (typeof data.html !== "string" || data.html.length < 1000 || data.html.length > 600000 ||
        !/<html\b/i.test(data.html) || !/<body\b/i.test(data.html) ||
        typeof data.sha !== "string" || !/^[a-f0-9]{40}$/.test(data.sha))
      return error("Некорректные данные сайта.", 400);
    const saved = await github(env, "PUT", "index.html", {
      message: "Content update from portfolio admin",
      content: base64FromUtf8(data.html),
      sha:data.sha,
      branch: env.GITHUB_BRANCH || "main"
    });
    return response({ ok:true, sha:saved.content.sha, commit:saved.commit.sha });
  }
  if (url.pathname === "/photo" && request.method === "PUT") {
    const data = await parseJson(request, 6500000);
    if (typeof data.base64 !== "string" || data.base64.length > 6000000 || data.base64.length < 500 ||
        !/^[A-Za-z0-9+/]+={0,2}$/.test(data.base64))
      return error("Нужна фотография JPG размером не более 4 МБ.",400);
    const head = atob(data.base64.slice(0,16));
    if (head.charCodeAt(0) !== 0xff || head.charCodeAt(1) !== 0xd8 || head.charCodeAt(2) !== 0xff)
      return error("Разрешены только изображения JPG.",400);
    const old = await github(env, "GET", "photo.jpg", null);
    const saved = await github(env, "PUT", "photo.jpg", {
      message: "Update portrait from portfolio admin",
      content:data.base64,
      sha:old.sha,
      branch:env.GITHUB_BRANCH || "main"
    });
    return response({ ok:true, commit:saved.commit.sha });
  }
  return error("Маршрут не найден.",404);
}
export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin");
    const allow = origin === env.SITE_ORIGIN;
    const cors = {
      "Vary": "Origin",
      "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      ...(allow ? {"Access-Control-Allow-Origin":origin}: {})
    };
    if (request.method === "OPTIONS")
      return new Response(null,{status:allow?204:403,headers:cors});
    if (origin && !allow) return response({error:"Недопустимый источник запроса."},403,cors);
    let result;
    try { result = await route(request,env); }
    catch (e) { result = error(e?.message || "Внутренняя ошибка сервера.",e?.status || 400); }
    const headers = new Headers(result.headers);
    for (const [k,v] of Object.entries(cors)) headers.set(k,v);
    headers.set("X-Content-Type-Options","nosniff");
    headers.set("Referrer-Policy","no-referrer");
    return new Response(result.body,{status:result.status,headers});
  }
};
