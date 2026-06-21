// functions/portfolio.js  —  Cloudflare Pages Function
// Saves/loads each signed-in user's virtual portfolio.
// Now accepts EITHER a Google id_token (a 3-part JWT) OR a session token issued by /auth:
//   Google users    -> key  pf:<google_sub>
//   Password users  -> key  pf:email:<emailLower>
// The token may arrive as ?credential=<...>, body.credential, or Authorization: Bearer <token>.
// The saved portfolio JSON shape is unchanged.
// Requires a KV namespace binding named PORTFOLIOS.
//   GET  /portfolio   (Bearer token or ?credential=)            -> { portfolio: {...}|null }
//   POST /portfolio   body: { portfolio } (+ Bearer or credential) -> { ok: true }

const FALLBACK_CLIENT_ID = '347224501690-l3u3m1photpe79gprq1939as322emjvl.apps.googleusercontent.com';

export async function onRequest(context) {
  const { request, env } = context;
  const headers = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' };

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: { ...headers, 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization' } });
  }

  const KV = env.PORTFOLIOS;
  if (!KV) return json({ error: 'storage not configured' }, 500, headers);
  const clientId = env.GOOGLE_CLIENT_ID || FALLBACK_CLIENT_ID;

  let body = null, credential = null;
  if (request.method === 'POST') {
    body = await request.json().catch(() => null);
    credential = body && body.credential;
  } else {
    credential = new URL(request.url).searchParams.get('credential');
  }
  // Authorization: Bearer <token> works for both GET and POST (used by password sessions,
  // and also fine for Google tokens).
  if (!credential) {
    const auth = request.headers.get('Authorization');
    if (auth && auth.startsWith('Bearer ')) credential = auth.slice(7);
  }
  if (!credential) return json({ error: 'no credential' }, 401, headers);

  // Decide auth type by token shape: a Google id_token is a 3-part JWT (has two dots);
  // our session token is opaque hex (no dots). We must NOT use a long JWT as a KV key.
  let key = null;
  if (String(credential).split('.').length === 3) {
    const claims = await verifyGoogle(credential, clientId);
    if (!claims) return json({ error: 'invalid token' }, 401, headers);
    key = 'pf:' + claims.sub;
  } else {
    const sess = await verifySession(KV, credential);
    if (!sess) return json({ error: 'invalid token' }, 401, headers);
    key = 'pf:email:' + String(sess.email).toLowerCase();
  }

  if (request.method === 'GET') {
    const v = await KV.get(key);
    return json({ portfolio: v ? JSON.parse(v) : null }, 200, headers);
  }
  if (request.method === 'POST') {
    const pf = body && body.portfolio;
    if (pf == null) return json({ error: 'no portfolio' }, 400, headers);
    const str = JSON.stringify(pf);
    if (str.length > 20000) return json({ error: 'too large' }, 413, headers);
    await KV.put(key, str);
    return json({ ok: true }, 200, headers);
  }
  return json({ error: 'method not allowed' }, 405, headers);
}

async function verifyGoogle(idToken, clientId) {
  try {
    const r = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(idToken));
    if (!r.ok) return null;
    const p = await r.json();
    if (p.aud !== clientId) return null;
    if (p.exp && (Date.now() / 1000) > Number(p.exp)) return null;
    if (!p.sub) return null;
    return p;
  } catch (e) { return null; }
}

async function verifySession(KV, token) {
  try {
    if (!token || String(token).length > 200) return null;
    const raw = await KV.get('sess:' + token);
    if (!raw) return null;
    const s = JSON.parse(raw);
    if (!s || !s.email) return null;
    if (s.exp && (Date.now() / 1000) > Number(s.exp)) return null;
    return s;
  } catch (e) { return null; }
}

function json(obj, status, headers) { return new Response(JSON.stringify(obj), { status, headers }); }
