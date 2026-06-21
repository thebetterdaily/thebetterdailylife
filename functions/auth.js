// functions/auth.js  —  Cloudflare Pages Function  (route: POST /auth)
// ---------------------------------------------------------------------------
// Email + password accounts for The Better Daily Life, alongside Google sign-in.
// Google stays the recommended easy default; this adds an email/password option.
//
// All actions are POST /auth with a JSON body { action, ... }:
//   action:"signup"          { email, password, newsletter }            -> { ok, token, email, newsletter, subscribed }
//   action:"login"           { email, password }                        -> { ok, token, email, newsletter }
//   action:"change-password" { oldPassword, newPassword } + Bearer token -> { ok }
//   action:"reset-request"   { email }                                  -> { ok }            (always ok; no account enumeration)
//   action:"reset-confirm"   { token, newPassword }                     -> { ok, token, email } (logs the user in)
//
// The session token is opaque (64 hex chars). The browser stores it and sends it
// as `Authorization: Bearer <token>` exactly like the Google id_token, and
// functions/portfolio.js accepts either one.
//
// KV (binding PORTFOLIOS) keys used here:
//   user:<emailLower>   -> { email, hash, createdAt, newsletter }
//   sess:<token>        -> { email, exp }      (auto-expires via KV TTL)
//   reset:<token>       -> { email, exp }      (1h, auto-expires)
//   rstwait:<emailLower>-> "1"                 (60s reset-email cooldown)
//
// Environment variables (set in Cloudflare → Pages → Settings → Environment variables):
//   GOOGLE_CLIENT_ID        (already set; used by portfolio.js/subscribe.js)
//   BEEHIIV_API_KEY         (already set; SECRET)  — newsletter opt-in at signup
//   BEEHIIV_PUBLICATION_ID  (already set)          — "pub_..."
//   RESEND_API_KEY          SECRET  — from resend.com, used to email reset links
//   RESEND_FROM             e.g. "The Better Daily Life <noreply@thebetterdailylife.com>"
//                                  (must be on your verified Resend domain;
//                                   for first tests you can use "onboarding@resend.dev",
//                                   which only delivers to your own Resend account email)
//   SITE_URL                e.g. "https://thebetterdailylife.com"  (reset links point here)
//   AUTH_DEBUG              "1" while testing -> reset-request returns the Resend result so
//                                  you can see send errors live. REMOVE it for production.
// ---------------------------------------------------------------------------

const PBKDF2_ITERATIONS = 100000; // floor from the plan. Stored per-hash, so it can be
                                  // raised/lowered later without breaking existing accounts.
                                  // NOTE: on the Workers *Free* plan (10ms CPU/request) very
                                  // high values can error. If signup/login ever times out,
                                  // lower this number; old accounts keep working.
const SALT_BYTES = 16;
const KEY_BITS = 256;
const SESSION_TTL = 60 * 60 * 24 * 30; // 30 days
const RESET_TTL = 60 * 60;             // 1 hour
const RESET_COOLDOWN = 60;             // min seconds between reset emails to one address

export async function onRequest(context) {
  const { request, env } = context;
  const headers = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' };

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: {
      ...headers,
      'Access-Control-Allow-Methods': 'POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    } });
  }
  if (request.method !== 'POST') return json({ ok: false, error: 'method_not_allowed' }, 405, headers);

  const KV = env.PORTFOLIOS;
  if (!KV) return json({ ok: false, error: 'storage_not_configured' }, 500, headers);

  const body = await request.json().catch(() => null);
  if (!body || typeof body !== 'object') return json({ ok: false, error: 'bad_request' }, 400, headers);

  const action = String(body.action || '');
  try {
    switch (action) {
      case 'signup':          return await signup(body, KV, env, headers);
      case 'login':           return await login(body, KV, headers);
      case 'change-password': return await changePassword(body, request, KV, headers);
      case 'reset-request':   return await resetRequest(body, KV, env, context, headers);
      case 'reset-confirm':   return await resetConfirm(body, KV, headers);
      default:                return json({ ok: false, error: 'unknown_action' }, 400, headers);
    }
  } catch (e) {
    return json({ ok: false, error: 'server_error', detail: String((e && e.message) || e) }, 500, headers);
  }
}

// ---------------------------- actions ----------------------------

async function signup(body, KV, env, headers) {
  const email = normEmail(body.email);
  if (!email) return json({ ok: false, error: 'invalid_email' }, 400, headers);
  const pwErr = passwordError(body.password);
  if (pwErr) return json({ ok: false, error: pwErr }, 400, headers);

  const userKey = 'user:' + email;
  if (await KV.get(userKey)) return json({ ok: false, error: 'account_exists' }, 409, headers);

  const hash = await createPasswordRecord(body.password);
  const newsletter = !!body.newsletter;
  await KV.put(userKey, JSON.stringify({ email, hash, createdAt: Date.now(), newsletter }));

  const token = await newSession(KV, email);

  // Newsletter opt-in handled here (server-side) so we don't depend on a brand-new
  // session being immediately readable from KV.
  let subscribed = false, subNote = null;
  if (newsletter) {
    const res = await beehiivSubscribe(env, email).catch(() => ({ ok: false, error: 'beehiiv_request_failed' }));
    subscribed = !!res.ok;
    if (!res.ok) subNote = res.error || 'beehiiv_error';
  }
  return json({ ok: true, token, email, newsletter, subscribed, subNote }, 200, headers);
}

async function login(body, KV, headers) {
  const email = normEmail(body.email);
  if (!email || !body.password) { await burnTime(body.password); return json({ ok: false, error: 'invalid_login' }, 401, headers); }

  const rec = await getUser(KV, email);
  if (!rec) { await burnTime(body.password); return json({ ok: false, error: 'invalid_login' }, 401, headers); }

  const ok = await verifyPassword(body.password, rec.hash);
  if (!ok) return json({ ok: false, error: 'invalid_login' }, 401, headers);

  const token = await newSession(KV, email);
  return json({ ok: true, token, email, newsletter: !!rec.newsletter }, 200, headers);
}

async function changePassword(body, request, KV, headers) {
  const token = bearer(request) || body.token;
  const sess = await getSession(KV, token);
  if (!sess) return json({ ok: false, error: 'not_authenticated' }, 401, headers);

  const rec = await getUser(KV, sess.email);
  if (!rec) return json({ ok: false, error: 'not_found' }, 404, headers);

  if (!(await verifyPassword(body.oldPassword || '', rec.hash))) {
    return json({ ok: false, error: 'wrong_password' }, 401, headers);
  }
  const pwErr = passwordError(body.newPassword);
  if (pwErr) return json({ ok: false, error: pwErr }, 400, headers);

  rec.hash = await createPasswordRecord(body.newPassword);
  await KV.put('user:' + sess.email, JSON.stringify(rec));
  return json({ ok: true }, 200, headers);
}

async function resetRequest(body, KV, env, context, headers) {
  const email = normEmail(body.email);
  const debug = env.AUTH_DEBUG === '1';
  const generic = () => json({ ok: true }, 200, headers); // uniform reply -> no account enumeration

  if (!email) return generic();
  if (!env.RESEND_API_KEY) return json({ ok: true, note: 'email_not_configured' }, 200, headers);

  const rec = await getUser(KV, email);
  if (!rec) return debug ? json({ ok: true, note: 'no_such_user' }, 200, headers) : generic();

  const waitKey = 'rstwait:' + email;
  if (await KV.get(waitKey)) return debug ? json({ ok: true, note: 'cooldown' }, 200, headers) : generic();
  await KV.put(waitKey, '1', { expirationTtl: RESET_COOLDOWN });

  const token = randomToken();
  await KV.put('reset:' + token, JSON.stringify({ email, exp: nowSec() + RESET_TTL }), { expirationTtl: RESET_TTL });

  const base = (env.SITE_URL || 'https://thebetterdailylife.com').replace(/\/+$/, '');
  const link = `${base}/?reset=${token}`;
  const from = env.RESEND_FROM || 'The Better Daily Life <noreply@thebetterdailylife.com>';

  const sendPromise = sendResetEmail(env.RESEND_API_KEY, from, email, link);
  if (debug) {
    const r = await sendPromise.catch(e => ({ ok: false, error: String(e) }));
    return json({ ok: true, debug: r }, 200, headers);
  }
  if (context && context.waitUntil) context.waitUntil(sendPromise.catch(() => {}));
  else await sendPromise.catch(() => {});
  return generic();
}

async function resetConfirm(body, KV, headers) {
  const token = String(body.token || '');
  if (!token || token.length > 200) return json({ ok: false, error: 'invalid_or_expired' }, 400, headers);

  const raw = await KV.get('reset:' + token);
  if (!raw) return json({ ok: false, error: 'invalid_or_expired' }, 400, headers);
  let info; try { info = JSON.parse(raw); } catch { return json({ ok: false, error: 'invalid_or_expired' }, 400, headers); }
  if (!info || !info.email || (info.exp && nowSec() > Number(info.exp))) {
    return json({ ok: false, error: 'invalid_or_expired' }, 400, headers);
  }
  const pwErr = passwordError(body.newPassword);
  if (pwErr) return json({ ok: false, error: pwErr }, 400, headers);

  const email = normEmail(info.email);
  const rec = await getUser(KV, email);
  if (!rec) return json({ ok: false, error: 'invalid_or_expired' }, 400, headers);

  rec.hash = await createPasswordRecord(body.newPassword);
  await KV.put('user:' + email, JSON.stringify(rec));
  await KV.delete('reset:' + token);

  const sessToken = await newSession(KV, email); // log in immediately after a successful reset
  return json({ ok: true, token: sessToken, email }, 200, headers);
}

// ------------------------ users / sessions ------------------------

async function getUser(KV, email) {
  const raw = await KV.get('user:' + email);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}
async function newSession(KV, email) {
  const token = randomToken();
  await KV.put('sess:' + token, JSON.stringify({ email, exp: nowSec() + SESSION_TTL }), { expirationTtl: SESSION_TTL });
  return token;
}
async function getSession(KV, token) {
  if (!token || String(token).length > 200) return null;
  const raw = await KV.get('sess:' + token);
  if (!raw) return null;
  let s; try { s = JSON.parse(raw); } catch { return null; }
  if (!s || !s.email) return null;
  if (s.exp && nowSec() > Number(s.exp)) return null;
  return s;
}

// ------------------------------ crypto ------------------------------

async function deriveBits(password, salt, iterations) {
  const enc = new TextEncoder();
  const km = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, km, KEY_BITS);
  return new Uint8Array(bits);
}
async function createPasswordRecord(password) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const hash = await deriveBits(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${b64(salt)}$${b64(hash)}`;
}
async function verifyPassword(password, stored) {
  const parts = String(stored || '').split('$'); // pbkdf2 $ iter $ saltB64 $ hashB64  (base64 has no '$')
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const iterations = parseInt(parts[1], 10);
  if (!iterations) return false;
  let salt, expected;
  try { salt = unb64(parts[2]); expected = unb64(parts[3]); } catch { return false; }
  const actual = await deriveBits(password, salt, iterations);
  return timingSafeEqual(actual, expected);
}
async function burnTime(password) {
  // Keep "no such user" timing close to a real verify (reduces account enumeration via timing).
  try { await deriveBits(String(password || ''), new Uint8Array(SALT_BYTES), PBKDF2_ITERATIONS); } catch {}
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

// ------------------------------- misc -------------------------------

function randomToken() {
  const a = crypto.getRandomValues(new Uint8Array(32));
  let s = ''; for (let i = 0; i < a.length; i++) s += a[i].toString(16).padStart(2, '0');
  return s; // 64 hex chars, never contains '.', so portfolio.js can tell it apart from a Google JWT
}
function normEmail(e) {
  if (typeof e !== 'string') return '';
  const v = e.trim().toLowerCase();
  if (v.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return '';
  return v;
}
function passwordError(p) {
  if (typeof p !== 'string' || !p.trim()) return 'invalid_password';
  if (p.length < 8) return 'password_too_short';
  if (p.length > 128) return 'password_too_long';
  return null;
}
function bearer(request) {
  const a = request.headers.get('Authorization') || '';
  return a.startsWith('Bearer ') ? a.slice(7) : null;
}
function nowSec() { return Math.floor(Date.now() / 1000); }
function b64(bytes) { let s = ''; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s); }
function unb64(str) { const bin = atob(str); const out = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; }

// ------------------------- external services -------------------------

async function sendResetEmail(apiKey, from, to, link) {
  const subject = 'Reset your The Better Daily Life password';
  const text = `We received a request to reset your password.

Reset it here (this link expires in 1 hour):
${link}

If you didn't request this, you can safely ignore this email.`;
  const html = `<div style="font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:480px;margin:0 auto;color:#111">
  <h2 style="margin:0 0 12px">Reset your password</h2>
  <p>We received a request to reset your <strong>The Better Daily Life</strong> password.</p>
  <p style="margin:20px 0"><a href="${link}" style="display:inline-block;background:#10b981;color:#fff;padding:11px 18px;border-radius:8px;text-decoration:none;font-weight:600">Choose a new password</a></p>
  <p style="color:#666;font-size:13px">This link expires in 1 hour. If you didn't request it, you can safely ignore this email.</p>
  <p style="color:#999;font-size:12px;word-break:break-all">${link}</p>
</div>`;
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from, to, subject, text, html })
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error('resend_' + r.status + ':' + JSON.stringify(data));
  return { ok: true, id: data.id };
}

async function beehiivSubscribe(env, email) {
  if (!env.BEEHIIV_API_KEY || !env.BEEHIIV_PUBLICATION_ID) return { ok: false, error: 'beehiiv_not_configured' };
  const r = await fetch(`https://api.beehiiv.com/v2/publications/${env.BEEHIIV_PUBLICATION_ID}/subscriptions`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.BEEHIIV_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email,
      reactivate_existing: true,
      send_welcome_email: true,
      utm_source: 'thebetterdailylife',
      utm_medium: 'financial-education',
      referring_site: 'thebetterdailylife.com'
    })
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) return { ok: false, error: 'beehiiv_error', detail: data };
  return { ok: true };
}

function json(obj, status, headers) { return new Response(JSON.stringify(obj), { status, headers }); }
