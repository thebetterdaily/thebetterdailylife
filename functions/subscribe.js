/**
 * Cloudflare Pages Function â€” POST /subscribe
 * ------------------------------------------------------------
 * Receives a Google sign-in token from the website, verifies it
 * with Google, and (if the user opted in) subscribes their email
 * to your Beehiiv newsletter.
 *
 * Your secret values are NOT in this file. You set them in the
 * Cloudflare dashboard as environment variables (see setup guide):
 *   GOOGLE_CLIENT_ID        â€“ your Google OAuth client id (also public-safe)
 *   BEEHIIV_API_KEY         â€“ SECRET. From Beehiiv â†’ Settings â†’ API
 *   BEEHIIV_PUBLICATION_ID  â€“ starts with "pub_". From Beehiiv API page
 * ------------------------------------------------------------
 */

export async function onRequestPost(context) {
  const { request, env } = context;

  // 1) read what the website sent
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "bad_request" }, 400);
  }
  const { credential, subscribe } = body || {};
  if (!credential) return json({ ok: false, error: "missing_credential" }, 400);

  // 2) verify the Google token is real (and was issued for YOUR app)
  let payload;
  try {
    const r = await fetch(
      "https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(credential)
    );
    if (!r.ok) return json({ ok: false, error: "invalid_token" }, 401);
    payload = await r.json();
  } catch {
    return json({ ok: false, error: "verify_failed" }, 502);
  }

  if (env.GOOGLE_CLIENT_ID && payload.aud !== env.GOOGLE_CLIENT_ID) {
    return json({ ok: false, error: "wrong_audience" }, 401);
  }
  if (payload.email_verified !== "true" && payload.email_verified !== true) {
    return json({ ok: false, error: "email_unverified" }, 401);
  }
  const email = payload.email;
  if (!email) return json({ ok: false, error: "no_email" }, 401);

  // 3) if they did not opt in, we're done (sign-in still succeeded)
  if (!subscribe) return json({ ok: true, subscribed: false, email });

  // 4) subscribe them to Beehiiv
  if (!env.BEEHIIV_API_KEY || !env.BEEHIIV_PUBLICATION_ID) {
    return json({ ok: true, subscribed: false, note: "beehiiv_not_configured", email });
  }
  try {
    const bee = await fetch(
      `https://api.beehiiv.com/v2/publications/${env.BEEHIIV_PUBLICATION_ID}/subscriptions`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.BEEHIIV_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email,
          reactivate_existing: true,
          send_welcome_email: true,
          utm_source: "thebetterdailylife",
          utm_medium: "financial-education",
          referring_site: "thebetterdailylife.com",
        }),
      }
    );
    const beeData = await bee.json().catch(() => ({}));
    if (!bee.ok) {
      return json({ ok: false, error: "beehiiv_error", detail: beeData }, 502);
    }
    return json({ ok: true, subscribed: true, email });
  } catch {
    return json({ ok: false, error: "beehiiv_request_failed" }, 502);
  }
}

// Block other methods politely
export async function onRequest(context) {
  if (context.request.method !== "POST") {
    return json({ ok: false, error: "method_not_allowed" }, 405);
  }
  return onRequestPost(context);
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
