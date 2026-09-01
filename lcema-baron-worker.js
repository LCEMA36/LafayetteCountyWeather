/**
 * LCEMA — Baron Weather signature broker (Cloudflare Worker)
 * ============================================================================
 * WHY THIS EXISTS
 *
 * Baron signs every request with HMAC-SHA1 over the string "<key>:<unix_ts>".
 * Generating that signature requires the API SECRET. The dashboard is a single
 * HTML file served from GitHub Pages, so anything in it is world-readable —
 * putting the secret there would hand the key to anyone who views source, and
 * they could burn the LCEMA transaction quota at will.
 *
 * The saving grace, verified against the live API on 2026-09-01: the signed
 * string contains ONLY the key and timestamp. It does NOT cover the URL path.
 * One signature therefore authorizes EVERY Baron request until it expires.
 *
 * So this Worker does exactly one thing: hand the page a short-lived signature.
 * The page then talks to Baron directly — tiles go browser -> Baron, never
 * through this Worker. No per-tile proxy bandwidth, no added latency, and the
 * secret never leaves Cloudflare.
 *
 * MEASURED SIGNATURE WINDOW (tested against api.velocityweather.com):
 *   ts 14 min old  -> 200      ts 15 min old  -> 403
 *   ts 10 min future -> 200    ts 20 min future -> 403
 * That is a +/- 15 minute window. The page should refresh every ~10 minutes.
 *
 * ---------------------------------------------------------------------------
 * DEPLOY
 *   1. npm i -g wrangler && wrangler login
 *   2. wrangler deploy lcema-baron-worker.js --name lcema-baron
 *   3. wrangler secret put BARON_SECRET     <- paste the secret, never commit it
 *      wrangler secret put BARON_KEY        <- the access key
 *   4. Put the resulting https://lcema-baron.<subdomain>.workers.dev URL into
 *      BARON_CONFIG.sigUrl in the dashboard.
 *
 * HONEST LIMITATION
 *   The Origin allow-list below is a browser-enforced control. Origin headers
 *   are trivially forged by anything that is not a browser (curl, a script), so
 *   this endpoint is not airtight — a determined party could pull signatures
 *   from it. What it does guarantee is that the secret itself is never exposed
 *   and that anything leaked is dead in 15 minutes, which is a categorically
 *   better failure mode than a permanently compromised key. If you want it
 *   tighter, add the Turnstile or shared-token check noted at the bottom.
 * ============================================================================
 */

// Every origin the dashboard is served from. capacitor://localhost is required
// by the iOS Capacitor build; the localhost entries are for local testing.
// Verified 2026-09-01 against the repo's Pages settings: the dashboard is served
// from https://lcema36.github.io/LafayetteCountyWeather/ (branch main, / root,
// no custom domain). An Origin is scheme + host only — no path — so the entry
// below is the whole origin, NOT the full page URL.
const ALLOWED_ORIGINS = new Set([
  'https://lcema36.github.io',         // GitHub Pages — LCEMA36/LafayetteCountyWeather
  'capacitor://localhost',             // iOS Capacitor shell
  'http://localhost:8080',
  'http://127.0.0.1:8080',
]);

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.has(origin);
  return {
    'Access-Control-Allow-Origin': allowed ? origin : 'null',
    'Access-Control-Allow-Methods': 'GET,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    // Responses differ per origin — never let a CDN collapse them into one.
    'Vary': 'Origin',
  };
}

function json(body, status, origin, extra) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...corsHeaders(origin),
      'Content-Type': 'application/json',
      // A signature is a credential with a 15-minute life. Never let a browser,
      // a proxy, or Cloudflare's own cache hold on to one.
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      ...(extra || {}),
    },
  });
}

/** HMAC-SHA1( "<key>:<ts>" ) -> URL-safe base64, exactly as Baron specifies. */
async function baronSignature(key, secret, ts) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
  );
  const mac = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(`${key}:${ts}`));
  // Baron's modified base64: '+' -> '-' and '/' -> '_' so it survives a URL.
  return btoa(String.fromCharCode(...new Uint8Array(mac)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }
    if (request.method !== 'GET') {
      return json({ error: 'method_not_allowed' }, 405, origin);
    }

    // ---- health check, no credentials issued -------------------------------
    if (url.pathname === '/health') {
      return json({
        ok: true,
        configured: Boolean(env.BARON_KEY && env.BARON_SECRET),
        time: new Date().toISOString(),
      }, 200, origin);
    }

    if (url.pathname !== '/sig') {
      return json({ error: 'not_found', hint: 'GET /sig' }, 404, origin);
    }

    if (!ALLOWED_ORIGINS.has(origin)) {
      return json({
        error: 'origin_not_allowed',
        origin: origin || '(none)',
        hint: 'Add this origin to ALLOWED_ORIGINS in the Worker and redeploy.',
      }, 403, origin);
    }

    const key = env.BARON_KEY;
    const secret = env.BARON_SECRET;
    if (!key || !secret) {
      // Say precisely what is missing — a silent empty signature would surface
      // downstream as an unexplained 403 on the radar tiles.
      return json({
        error: 'worker_not_configured',
        detail: 'BARON_KEY and/or BARON_SECRET secret is not set on this Worker.',
        fix: 'wrangler secret put BARON_KEY  /  wrangler secret put BARON_SECRET',
      }, 500, origin);
    }

    try {
      const ts = Math.floor(Date.now() / 1000).toString();
      const sig = await baronSignature(key, secret, ts);
      return json({
        key,            // the access key is not secret; the page needs it in the URL
        sig,
        ts,
        // Baron's measured window is +/- 15 min. Advertise 10 so the page always
        // rotates with margin to spare rather than racing the expiry.
        expires_in: 600,
        issued: new Date().toISOString(),
      }, 200, origin);
    } catch (err) {
      return json({ error: 'signing_failed', detail: String(err && err.message || err) }, 500, origin);
    }
  },
};

/* ---------------------------------------------------------------------------
 * OPTIONAL HARDENING — add if you want more than the Origin check
 *
 * 1. Shared token. Put a random string in the Worker as env.LCEMA_TOKEN and in
 *    the dashboard as BARON_CONFIG.token, then require ?t=<token> on /sig.
 *    It is still visible in page source, but it stops drive-by use of the
 *    endpoint by anyone who has not read your source.
 *
 * 2. Rate limit per IP with a Durable Object or KV counter — e.g. 30 signatures
 *    per IP per hour. A dashboard needs ~6 per hour; anything far above that is
 *    not the EOC display.
 *
 * 3. Cloudflare Turnstile in front of /sig for a human-only guarantee. Heavier
 *    than this use case probably warrants for a wall display that must come up
 *    unattended after a power blip.
 * ------------------------------------------------------------------------- */
