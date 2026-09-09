/**
 * Login bridge — turns "the gateway says you are a platform admin" into
 * "Umami thinks you are signed in".
 *
 * WHY THIS EXISTS
 *
 * The platform gateway authenticates a browser (openid-connect against
 * Keycloak) and authorizes it (`requiredRoles: [platform-admin]` in
 * auth-verify.lua). What it cannot do is make Umami believe any of that:
 * Umami has its own user table, no SSO, and no knowledge of X-User-Roles.
 * Left alone, a cleared platform admin still lands on Umami's password prompt.
 *
 * So this sits in front of Umami and does one thing: on the bare entry path it
 * mints a short-lived Umami session for a READ-ONLY service account and hands
 * the browser to Umami's own /sso page, which stores the token and redirects.
 * Every other path is proxied through untouched — once the browser holds the
 * token it authenticates itself, and this process is just a pipe.
 *
 * WHAT IT IS NOT
 *
 * Not a security boundary. It trusts the gateway completely, because the
 * gateway is the only way to reach it (the Service is ClusterIP and the only
 * published routes point here). The role check happens there, in Lua, before
 * this process sees the request. The re-check below is defence in depth
 * against a misconfigured route, not the primary control.
 *
 * Runs from the umami image itself (same Node, different command), so it adds
 * no second image to the build pipeline.
 */

import http from 'node:http';

const PORT = Number(process.env.BRIDGE_PORT || 3001);
const UMAMI = (process.env.UMAMI_INTERNAL_URL || 'http://127.0.0.1:3000').replace(/\/$/, '');
const BASE_PATH = (process.env.BASE_PATH || '').replace(/\/$/, '');
const USERNAME = process.env.UMAMI_STAFF_USER || '';
const PASSWORD = process.env.UMAMI_STAFF_PASSWORD || '';
const ROLE_HEADER = 'x-user-roles';
const REQUIRED_ROLE = process.env.BRIDGE_REQUIRED_ROLE || 'platform-admin';

/**
 * Calls this proxy refuses outright, whatever the caller's Umami role.
 *
 * The service account is a full Umami admin on purpose -- a platform admin
 * signing in here should be able to build and save reports, organise boards
 * and manage teams, and Umami has no role that allows those while withholding
 * site deletion. Every role above "nothing" carries websiteDelete.
 *
 * So the line is drawn here instead, and now around one call:
 *
 *   POST /api/websites/{id}/reset   erases a site's events
 *
 * DELETE /api/websites/{id} WAS REFUSED HERE AND DELIBERATELY IS NOT ANY MORE,
 * so staff can clean up sites -- test sites especially -- from the dashboard.
 * The reasoning it overrode is kept rather than deleted, because the failure
 * mode is quiet and whoever meets it should not have to rediscover why:
 *
 *   The site id a tracker posts to is DERIVED (a hash of the environment host
 *   plus the chart name), not stored. So a deleted site is recreated under the
 *   SAME id by the next deploy's provisioning call -- empty. Ingestion silently
 *   resumes into a blank site, the dashboard still loads, and the charts just
 *   start from zero. No error to notice, and nothing to restore.
 *
 * This changes what is convenient, not what is possible: Umami's API is
 * reachable directly on the pod (127.0.0.1:3000), which this list never
 * covered, so deletion was always available to anyone with pod access.
 *
 * NOTE this default is a FALLBACK, not the deployed policy. The chart sets
 * BRIDGE_BLOCKED_CALLS from `bridge.blockedCalls` whenever that list is
 * non-empty, so the values file wins. Keep the two in step: an environment
 * that wants deletion re-blocked adds the pattern back there, not here.
 *
 * A denylist is normally the weaker pattern, but the surface here is a fixed
 * endpoint in a third-party API we do not control, so enumerating it is both
 * tractable and easier to review than the alternative.
 */
const BLOCKED = (process.env.BRIDGE_BLOCKED_CALLS ||
  'POST:^/api/websites/[^/]+/reset/?$')
  .split(',')
  .map(entry => entry.trim())
  .filter(Boolean)
  .map(entry => {
    const [method, pattern] = entry.split(':');
    return { method: method.toUpperCase(), re: new RegExp(pattern) };
  });
/**
 * Where Umami is sent after the hand-off, and why it is NOT "/".
 *
 * With basePath baked in, Umami's "/" IS /umami -- the same URL as this
 * bridge's entry path. Sending the browser there after a successful hand-off
 * put it straight back on the mint path, which minted again, redirected to
 * /sso again, and looped forever. Landing on a real page instead means the
 * hand-off can never return to the entry path.
 *
 * /websites is where Umami's own root page redirects anyway (src/app/page.tsx
 * does router.replace('/websites')), so this skips a hop rather than changing
 * the destination.
 */
const POST_SIGNIN_PATH = process.env.BRIDGE_POST_SIGNIN_PATH || '/websites';

/**
 * Short-lived marker that this browser was just handed a token.
 *
 * Belt to POST_SIGNIN_PATH's braces. Anything that lands back on the entry
 * path -- Umami's own header logo links to "/", which is /umami -- would
 * otherwise mint a fresh token on every click. While this cookie is present
 * the entry path is proxied through instead, and Umami's root page does its
 * own client-side redirect using the token already in localStorage.
 *
 * Deliberately ~2 minutes, not the token's 24h. It exists to break redirect
 * loops, not to suppress legitimate re-minting: if someone clears localStorage
 * an hour later, they must be able to hit /umami and get a working session
 * rather than be proxied to a login page they cannot pass.
 */
const RECENT_MINT_COOKIE = 'umami_bridge_signin';
const RECENT_MINT_TTL_S = 120;

/**
 * Where an app asks for its own analytics site.
 *
 * Deliberately a path this bridge answers itself rather than one it proxies:
 * Umami's own admin API is not reachable from the edge (the gateway publishes
 * only the tracker script and the event collector anonymously; everything else
 * under the prefix is behind a browser sign-in a server-to-server call cannot
 * complete). This is the one narrow, create-only opening onto it.
 */
const PROVISION_PATH = process.env.BRIDGE_PROVISION_PATH || '/provision';

/**
 * Where an app reads its OWN numbers back.
 *
 * A NAMED endpoint, emphatically not a proxy onto Umami's API. Publishing
 * /api/websites/{id}/* to apps would hand every one of them most of the
 * dashboard API under a shared key -- including calls that MUTATE. The denylist
 * above refuses ONE call, reset; site deletion was deliberately opened up so
 * staff can clean up test sites. So a proxy would let any app delete any site,
 * and 'read-only' would be an assumption rather than a property.
 *
 * So this makes exactly three upstream calls, with a fixed response shape. An
 * app never reaches Umami's API surface, and widening what apps can see is a
 * deliberate edit here rather than an accident of routing.
 *
 * Aggregates only, never raw event rows. The write path deliberately strips
 * record ids out of URLs, drops query strings whole and never sends page titles;
 * handing per-visit rows back would undo that on the way out.
 */
const INSIGHTS_PATH = process.env.BRIDGE_INSIGHTS_PATH || '/insights';

/**
 * A window cap, so no app can ask Umami to scan all of history. Seven days is
 * the default when the caller names no window -- the common case is a dashboard
 * tile, not an audit.
 */
const INSIGHTS_MAX_DAYS = Number(process.env.BRIDGE_INSIGHTS_MAX_DAYS || 90);
const INSIGHTS_DEFAULT_DAYS = Number(
  process.env.BRIDGE_INSIGHTS_DEFAULT_DAYS || 7,
);
const INSIGHTS_TOP_N = Number(process.env.BRIDGE_INSIGHTS_TOP_N || 10);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const log = (...args) => console.log('[bridge]', ...args);

/**
 * Register this app's paths with genesis-authz at startup.
 *
 * genesis-authz default-denies any URI it does not recognise -- a deliberate
 * safety net so a new endpoint cannot ship with no authorization by accident.
 * Umami's paths therefore have to be declared, or every request 403s before
 * the gateway's platform-admin gate is ever consulted.
 *
 * Declared HERE rather than hardcoded into genesis-authz, per its own route
 * registration contract: a service owns its route list and sends the whole
 * thing on every boot, so the table converges without anyone editing another
 * repository. Umami is third-party and cannot make this call itself, so the
 * bridge -- which already sits in its pod and is our code -- makes it.
 *
 * `bypass` is the right kind: it means "skip the OpenFGA resource check, still
 * require authentication". There is no Umami resource modelled in FGA, and the
 * authorization for this tree is the gateway's requiredRoles gate.
 */
const AUTHZ_URL = (process.env.AUTHZ_INTERNAL_URL || '').replace(/\/$/, '');
const AUTHZ_KEY = process.env.AUTHZ_INTERNAL_KEY || '';
const ROUTE_SERVICE_NAME = process.env.AUTHZ_SERVICE_NAME || 'umami';
// Umami's own routes reach six segments below its prefix (e.g.
// /api/websites/{id}/event-data/values). The registration compiler anchors
// every pattern and its widest param type matches a single segment, so a
// subtree needs one row per depth. Nine covers today's tree with room for an
// upstream release to add two more levels before this needs revisiting.
const ROUTE_MAX_DEPTH = Number(process.env.AUTHZ_ROUTE_MAX_DEPTH || 9);

function buildRoutePayload() {
  const prefix = BASE_PATH || '/umami';
  const routes = [{ kind: 'bypass', pattern_template: prefix, params: [] }];

  for (let depth = 1; depth <= ROUTE_MAX_DEPTH; depth++) {
    const names = Array.from({ length: depth }, (_, i) => `s${i}`);
    routes.push({
      kind: 'bypass',
      pattern_template: `${prefix}/${names.map(n => `{${n}}`).join('/')}`,
      // `any` is one path segment. Segment count is what the depth expresses.
      params: names.map(name => ({ name, type: 'any' })),
    });
  }

  return { service_name: ROUTE_SERVICE_NAME, routes };
}

async function registerRoutes(attempt = 1) {
  if (!AUTHZ_URL || !AUTHZ_KEY) {
    log('route registration skipped — AUTHZ_INTERNAL_URL/KEY not set');
    return;
  }

  try {
    const res = await fetch(`${AUTHZ_URL}/internal/authz/routes/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Internal-Call': AUTHZ_KEY },
      body: JSON.stringify(buildRoutePayload()),
    });

    if (res.ok) {
      log(`registered ${ROUTE_MAX_DEPTH + 1} route patterns with genesis-authz`);
      return;
    }

    const detail = await res.text().catch(() => '');
    throw new Error(`${res.status} ${detail.slice(0, 300)}`);
  } catch (err) {
    // Loud, because the dashboard 403s until this succeeds -- but never fatal.
    // A transient authz outage at boot must not leave the route permanently
    // broken until someone notices and restarts the pod, so this retries with
    // backoff instead of giving up after one attempt.
    log(`route registration attempt ${attempt} failed: ${err.message}`);
    if (attempt >= 10) {
      // Deliberately hedged. Registration is full-replace and the rows persist
      // in genesis-authz's database, so a failure here is only fatal on an
      // instance that has NEVER registered successfully. On every other one
      // the previous rows are still serving and the dashboard is unaffected.
      // Saying "/umami will 403" flatly was wrong, and wrong in the worst
      // place: someone reading this line mid-incident would chase a dead end.
      log(
        'route registration gave up after 10 attempts. If this instance has ' +
        'registered before, the existing rows in genesis-authz still apply and ' +
        '/umami keeps working; only a first-ever registration leaves it 403ing. ' +
        'Check genesis-authz health, then restart this pod to retry.',
      );
      return;
    }
    setTimeout(() => registerRoutes(attempt + 1), Math.min(30000, 2000 * attempt));
  }
}

/**
 * The service account's own long-lived token. Umami's /api/auth/login issues a
 * token with NO expiry (saveAuth is called without one), so this is cached in
 * memory for the life of the pod and deliberately never reaches a browser.
 * Only the short-lived token minted from it does.
 */
let serviceToken = null;

async function getServiceToken() {
  if (serviceToken) return serviceToken;

  if (!USERNAME || !PASSWORD) {
    throw new Error('UMAMI_STAFF_USER / UMAMI_STAFF_PASSWORD are not set');
  }

  // NOTE the BASE_PATH. The image is built with basePath baked in, so Umami
  // serves its own API under that prefix too -- /umami/api/auth/login, not
  // /api/auth/login. UMAMI stays prefix-free because proxied requests already
  // carry it in req.url; only the calls the bridge makes ITSELF have to add it.
  // Without this every sign-in fails with a bare 404 and the entry path 502s.
  const res = await fetch(`${UMAMI}${BASE_PATH}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: USERNAME, password: PASSWORD }),
  });

  if (!res.ok) {
    throw new Error(`login failed: ${res.status}`);
  }

  const body = await res.json();
  if (!body?.token) throw new Error('login returned no token');

  serviceToken = body.token;
  return serviceToken;
}

/**
 * Run an authenticated call against Umami, re-logging in once if the cached
 * service token is rejected.
 *
 * WHY THIS EXISTS
 *
 * The cached token can stop working while the pod is perfectly healthy: the
 * staff password was rotated, APP_SECRET changed, or the staff-setup Job
 * recreated the account. Every path here used to handle that by clearing the
 * cache and throwing "cleared for retry" -- which fixed the NEXT caller and
 * failed the current one.
 *
 * That is a bad trade for both callers. A staff member got a 502 signing in and
 * had to click again for no visible reason. Worse, an app provisioning its
 * analytics site got a 502 at startup, and its site is created ONCE per boot --
 * so a single stale token cost that app its analytics until the next deploy,
 * silently. Both were observed on dev: a 502, then success on the very next
 * attempt with nothing else changed.
 *
 * The token is cheap to re-mint (one login against a process in the same pod)
 * and staleness is exactly the condition a retry fixes, so the retry belongs
 * here rather than in every caller.
 *
 * Bounded at one extra attempt on purpose: two 401s in a row is a credential
 * problem, not a stale cache, and looping would bury that behind a hang.
 */
async function withServiceToken(call) {
  const first = await call(await getServiceToken());
  if (first.status !== 401) return first;

  log('service token rejected; re-logging in and retrying once');
  serviceToken = null;

  const second = await call(await getServiceToken());
  if (second.status === 401) {
    // Clear again so a caller after this one starts clean, but say plainly that
    // a fresh login was also refused -- that is a credential fault, and the
    // old "cleared for retry" wording sent people looking for a cache bug.
    serviceToken = null;
    throw new Error(
      'service token rejected even after re-login -- check UMAMI_STAFF_USER / ' +
      'UMAMI_STAFF_PASSWORD and that the staff account still exists',
    );
  }
  return second;
}

/**
 * Mint the token the browser actually receives.
 *
 * /api/auth/sso is the ONLY Umami endpoint that produces an expiring token —
 * it calls saveAuth(..., 86400) where /api/auth/login passes no expiry at all.
 * That expiry is the whole reason this goes through /sso rather than handing
 * over the login token directly.
 *
 * It requires Redis (the route returns 500 "Redis is disabled" otherwise),
 * which is why REDIS_URL is a hard prerequisite for the chart, not a nicety.
 */
async function mintBrowserToken() {
  const res = await withServiceToken(token =>
    fetch(`${UMAMI}${BASE_PATH}/api/auth/sso`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    }),
  );

  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`sso mint failed: ${res.status} ${detail.slice(0, 200)}`);
  }

  const body = await res.json();
  if (!body?.token) throw new Error('sso returned no token');

  return body.token;
}

function hasRequiredRole(req) {
  const raw = req.headers[ROLE_HEADER];
  if (!raw) return false;
  return String(raw)
    .split(',')
    .map(r => r.trim())
    .includes(REQUIRED_ROLE);
}

/**
 * Strip the base path so matching is written against Umami's own routes rather
 * than the prefix we happen to serve it under.
 */
function appPath(pathname) {
  return BASE_PATH && pathname.startsWith(BASE_PATH)
    ? pathname.slice(BASE_PATH.length) || '/'
    : pathname;
}

function mintedRecently(req) {
  const raw = req.headers.cookie || '';
  return raw.split(';').some(c => c.trim().startsWith(`${RECENT_MINT_COOKIE}=`));
}

function isBlocked(method, pathname) {
  const p = appPath(pathname);
  return BLOCKED.some(b => b.method === (method || '').toUpperCase() && b.re.test(p));
}

function isEntryPath(pathname) {
  // Only the bare entry. A deep link is proxied straight through: the browser
  // either already holds a token (normal case) or gets Umami's login page,
  // and visiting the entry path fixes it. Intercepting every path would mint
  // a token on every asset request.
  const stripped = appPath(pathname);
  return stripped === '' || stripped === '/';
}

function isProvisionPath(pathname) {
  return appPath(pathname) === PROVISION_PATH;
}

function isInsightsPath(pathname) {
  return appPath(pathname) === INSIGHTS_PATH;
}

/**
 * Create the analytics site for an app, if it does not already exist.
 *
 * WHY THIS LIVES HERE
 *
 * The alternative is giving every app a Umami login so it can create its own
 * site. Umami's roles are a fixed constant and the weakest one that can create
 * a website (`user`) also carries website:delete -- and deleting a site drops
 * its events, replays, heatmaps and revenue rows in one transaction and then
 * hard-deletes the site, with no soft-delete path outside CLOUD_MODE, which is
 * not set. A create-only capability does not exist in Umami, so it has to be
 * made: the credential stays here, behind a call that only ever creates.
 *
 * The bridge is already signed in as the staff account for the dashboard
 * hand-off, so it needs no new credential -- and because Umami records
 * `userId = auth.user.id` on create, a site made here is owned by that account
 * from the first moment. It shows up on the staff Websites page immediately,
 * with no ownership transfer and no window where a new app's site is invisible.
 *
 * IDEMPOTENT BY ID, NOT BY NAME
 *
 * The caller supplies the id it already computed from its own chart, so this is
 * an upsert rather than a create: same app, same id, every time. Every replica
 * calls this on every start and only the first one does anything. Matching on
 * name instead would make two apps with the same display name collide.
 */
async function provisionSite({ websiteId, name, domain }) {
  // Both calls go through withServiceToken, so a stale cached token costs a
  // re-login rather than this app's analytics. Each resolves the token when it
  // runs -- the create below must not reuse a token the lookup just replaced.
  const existing = await withServiceToken(token =>
    fetch(`${UMAMI}${BASE_PATH}/api/websites/${websiteId}`, {
      headers: { Authorization: `Bearer ${token}` },
    }),
  );

  if (existing.ok) {
    const body = await existing.json().catch(() => null);
    // A 200 with a null body is Umami's "not found" for this endpoint, so the
    // body is checked rather than the status alone.
    if (body?.id) return { created: false, websiteId: body.id };
  }

  const res = await withServiceToken(token =>
    fetch(`${UMAMI}${BASE_PATH}/api/websites`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: websiteId, name, domain }),
    }),
  );

  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`create failed: ${res.status} ${detail.slice(0, 200)}`);
  }

  return { created: true, websiteId };
}

async function handleProvision(req, res) {
  if ((req.method || '').toUpperCase() !== 'POST') {
    deny(res, 405, 'Use POST to provision an analytics site.');
    return;
  }

  let payload;
  try {
    payload = JSON.parse(await readBody(req));
  } catch (err) {
    if (err?.tooLarge) {
      // Status first, then hang up: the caller learns why, and the rest of
      // whatever they were sending is not read.
      deny(res, 413, 'Request body is larger than this endpoint accepts.');
      req.destroy();
      return;
    }
    deny(res, 400, 'Body must be JSON.');
    return;
  }

  const { websiteId, name, domain } = payload || {};

  // The id is the app's own computed value, so it is validated rather than
  // trusted: a malformed one would create a site nothing can ever address.
  if (!UUID_RE.test(websiteId || '')) {
    deny(res, 400, 'websiteId must be a uuid the calling app computed for itself.');
    return;
  }
  if (!name || !domain) {
    deny(res, 400, 'name and domain are required.');
    return;
  }

  try {
    const result = await provisionSite({ websiteId, name, domain });
    log('provision', result.created ? 'created' : 'already present', websiteId, name);
    res.writeHead(result.created ? 201 : 200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
  } catch (err) {
    // 502, not 500: the failure is upstream in Umami, and the caller is a
    // deploy-time script that should log and carry on rather than crash.
    log('provision failed', websiteId, '--', err.message);
    deny(res, 502, 'Could not provision the analytics site.');
  }
}

/**
 * Resolve the requested window to two epoch-millisecond bounds.
 *
 * Accepts `from`/`to` as either epoch millis or anything Date can parse, so a
 * caller can send an ISO date without formatting gymnastics. Returns an
 * { error } instead of throwing, because every failure here is a 400 the caller
 * needs explained rather than an exception.
 */
function resolveWindow(params) {
  const parse = (raw, fallback) => {
    if (!raw) return fallback;
    const asNumber = Number(raw);
    const ms =
      Number.isFinite(asNumber) && String(asNumber) === String(raw).trim()
        ? asNumber
        : Date.parse(raw);
    return Number.isFinite(ms) ? ms : NaN;
  };

  const to = parse(params.get('to'), Date.now());
  const from = parse(params.get('from'), to - INSIGHTS_DEFAULT_DAYS * 86400000);

  if (!Number.isFinite(from) || !Number.isFinite(to)) {
    return { error: 'from/to must be epoch milliseconds or a parseable date.' };
  }
  if (from >= to) return { error: '`from` must be earlier than `to`.' };

  const days = (to - from) / 86400000;
  if (days > INSIGHTS_MAX_DAYS) {
    return {
      error:
        `Window is ${Math.ceil(days)} days; the maximum is ` +
        `${INSIGHTS_MAX_DAYS}. Ask for a narrower range.`,
    };
  }
  return { from: Math.floor(from), to: Math.floor(to) };
}

/**
 * One authenticated GET against Umami, returning parsed JSON.
 *
 * Goes through withServiceToken so a stale cached token costs a re-login rather
 * than the caller's request -- the same reason provisioning does.
 */
async function umamiGet(path) {
  const res = await withServiceToken((token) =>
    fetch(`${UMAMI}${BASE_PATH}${path}`, {
      headers: { Authorization: `Bearer ${token}` },
    }),
  );
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(
      `${path.split('?')[0]} returned ${res.status} ${detail.slice(0, 120)}`,
    );
  }
  return res.json();
}

/**
 * Read one site's aggregated numbers.
 *
 * WHAT THIS DELIBERATELY IS NOT
 *
 * Not a proxy. Three fixed upstream calls, one fixed response shape. See the
 * INSIGHTS_PATH comment for why that distinction is the whole point.
 *
 * WHAT IT DOES NOT ENFORCE
 *
 * Ownership. Every app presents the same platform key, so the gateway cannot
 * tell one app from another and this endpoint serves whatever site id it is
 * given. An app that knows another app's id can read that app's numbers, and
 * the ids are derived from host + chart name, so they are guessable.
 *
 * That is a decision, not an oversight: app-level isolation would require a key
 * per app, and the trade was judged not worth it for internal apps. If it ever
 * becomes worth it, the shape to add is an ownership tuple in genesis-authz --
 * recorded at provision time, checked here -- and nothing else about this
 * endpoint changes.
 */
async function handleInsights(req, res) {
  if ((req.method || '').toUpperCase() !== 'GET') {
    deny(res, 405, 'Use GET to read analytics.');
    return;
  }

  const params = new URL(req.url, 'http://localhost').searchParams;
  const site = (params.get('site') || '').trim();

  // Validated, not trusted: this value is interpolated into an upstream URL.
  if (!UUID_RE.test(site)) {
    deny(res, 400, 'site must be the uuid of an analytics site.');
    return;
  }

  const window = resolveWindow(params);
  if (window.error) {
    deny(res, 400, window.error);
    return;
  }

  try {
    // Existence first, because /stats answers 200 with zeros for a site that
    // does not exist. Without this an app with a wrong id reads 'no traffic'
    // and concludes its analytics is broken rather than its id is.
    const site_row = await umamiGet(`/api/websites/${site}`);
    if (!site_row?.id) {
      deny(
        res,
        404,
        'No analytics site with that id. Has the app provisioned yet?',
      );
      return;
    }

    const range = `startAt=${window.from}&endAt=${window.to}`;
    const [stats, pages, referrers] = await Promise.all([
      umamiGet(`/api/websites/${site}/stats?${range}`),
      // `path`, not `url` -- Umami's metrics endpoint validates `type` against
      // EVENT_COLUMNS (src/lib/constants.ts) and refuses anything else with a
      // bare 400. Checked against the source, not guessed.
      umamiGet(
        `/api/websites/${site}/metrics?type=path&${range}&limit=${INSIGHTS_TOP_N}`,
      ),
      umamiGet(
        `/api/websites/${site}/metrics?type=referrer&${range}&limit=${INSIGHTS_TOP_N}`,
      ),
    ]);

    // `{x, y}` is Umami's shape for a metrics row. Renamed on the way out so an
    // app is not coupled to it -- this response is the contract, Umami's is not.
    const rows = (list) =>
      (Array.isArray(list) ? list : []).map((r) => ({ name: r.x, views: r.y }));

    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    });
    res.end(
      JSON.stringify({
        site,
        window: {
          from: new Date(window.from).toISOString(),
          to: new Date(window.to).toISOString(),
        },
        totals: {
          pageviews: stats?.pageviews ?? 0,
          visitors: stats?.visitors ?? 0,
          visits: stats?.visits ?? 0,
          bounces: stats?.bounces ?? 0,
          // Umami reports seconds; named so nobody has to guess the unit.
          total_time_seconds: stats?.totaltime ?? 0,
        },
        top_pages: rows(pages),
        top_referrers: rows(referrers),
      }),
    );
  } catch (err) {
    // 502: the failure is upstream in Umami. The caller is an app rendering a
    // page and should degrade rather than break, so the message stays generic
    // and the detail goes to the log.
    log('insights failed', site, '--', err.message);
    deny(res, 502, 'Could not read analytics for that site.');
  }
}

/**
 * A provisioning body is three short fields. Anything larger is a mistake or an
 * attack, and this endpoint is reachable by every app on the platform.
 */
const MAX_BODY_BYTES = 4096;

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    let settled = false;

    // Rejecting alone is not enough: the promise settles but the socket keeps
    // delivering, and `data` keeps growing. A client streaming a gigabyte would
    // have all of it buffered here long after the caller gave up.
    //
    // So accumulation stops at the flag and the stream is paused -- not
    // destroyed. Destroying here would tear the socket down before the caller
    // could write a status, and the client would see a connection reset with no
    // idea why. The caller sends 413 and closes it afterwards.
    const stop = err => {
      if (settled) return;
      settled = true;
      req.pause();
      reject(err);
    };

    req.on('data', chunk => {
      if (settled) return;
      data += chunk;
      if (data.length > MAX_BODY_BYTES) stop(Object.assign(new Error('body too large'), { tooLarge: true }));
    });
    req.on('end', () => {
      if (settled) return;
      settled = true;
      resolve(data);
    });
    req.on('error', stop);
  });
}

function deny(res, status, message) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: message }));
}

function proxy(req, res) {
  const upstream = http.request(
    UMAMI + req.url,
    { method: req.method, headers: req.headers },
    up => {
      res.writeHead(up.statusCode || 502, up.headers);
      up.pipe(res);
    },
  );

  upstream.on('error', err => {
    log('upstream error:', err.message);
    if (!res.headersSent) deny(res, 502, 'Analytics service unavailable');
    else res.end();
  });

  req.pipe(upstream);
}

const server = http.createServer(async (req, res) => {
  // Liveness for the sidecar itself. Deliberately before every other check so
  // kubelet never needs a role header.
  if (req.url === '/bridge-healthz') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }

  const pathname = new URL(req.url, 'http://localhost').pathname;

  // Checked before anything else routes: a destructive call must not depend on
  // any later branch behaving as expected.
  if (isBlocked(req.method, pathname)) {
    log('refused', req.method, pathname, '-- destructive call');
    deny(res, 403, 'Deleting or resetting an analytics site is not permitted here. Sites are managed by deployment automation.');
    return;
  }

  // After the denylist, so provisioning can never become a way around it, and
  // before the proxy, so this path is answered here rather than forwarded to
  // Umami as if it were a page.
  //
  // No role check: the caller is a deploying app, not a browser, and it carries
  // an app key the gateway has already validated -- there is no platform-admin
  // in this request to look for.
  if (isProvisionPath(pathname)) {
    // Guarded at the dispatch point, not only inside the handler. This
    // callback is async, so anything that escapes it becomes an unhandled
    // rejection -- and Node exits the process on those. A client that hangs up
    // mid-write would take the sidecar down with it, and this sidecar shares a
    // pod with Umami itself.
    try {
      await handleProvision(req, res);
    } catch (err) {
      log('provision handler failed unexpectedly --', err.message);
      if (!res.headersSent) deny(res, 502, 'Could not provision the analytics site.');
    }
    return;
  }

  // Same placement rationale as provisioning: after the denylist so this can
  // never become a way around it, and before the proxy so the path is answered
  // here rather than forwarded to Umami as if it were a page.
  //
  // No role check. The caller is an app, not a browser, carrying a platform key
  // the gateway has already validated -- there is no platform-admin in this
  // request to look for.
  if (isInsightsPath(pathname)) {
    // Guarded at the dispatch point for the same reason as above: an escaped
    // rejection from this async callback would exit the process.
    try {
      await handleInsights(req, res);
    } catch (err) {
      log('insights handler failed unexpectedly --', err.message);
      if (!res.headersSent) deny(res, 502, 'Could not read analytics.');
    }
    return;
  }

  // Proxy the entry path through when this browser was just handed a token.
  // Without it, anything returning to /umami re-mints -- and before
  // POST_SIGNIN_PATH existed, that was an infinite redirect loop.
  if (!isEntryPath(pathname) || mintedRecently(req)) {
    proxy(req, res);
    return;
  }

  // Defence in depth. The gateway already enforced this; if the header is
  // missing the route is misconfigured, and failing closed makes that loud
  // instead of silently handing out a session.
  if (!hasRequiredRole(req)) {
    log('entry refused: no', REQUIRED_ROLE, 'in', ROLE_HEADER);
    deny(res, 403, `This dashboard requires the ${REQUIRED_ROLE} role`);
    return;
  }

  try {
    const token = await mintBrowserToken();
    // Umami's /sso page validates `url` against open redirects itself
    // (isSafeRedirectUrl: must start with a single slash, no scheme).
    const target =
      `${BASE_PATH}/sso?token=${encodeURIComponent(token)}` +
      `&url=${encodeURIComponent(POST_SIGNIN_PATH)}`;
    res.writeHead(302, {
      Location: target,
      // A URL carrying a session token must never be cached or revalidated.
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      Pragma: 'no-cache',
      'Set-Cookie':
        `${RECENT_MINT_COOKIE}=1; Path=${BASE_PATH || '/'}; Max-Age=${RECENT_MINT_TTL_S}; ` +
        'HttpOnly; SameSite=Lax',
    });
    res.end();
  } catch (err) {
    log('sign-in failed:', err.message);
    deny(res, 502, 'Could not sign in to analytics');
  }
});

server.listen(PORT, '0.0.0.0', () => {
  log(`listening on ${PORT}, proxying ${UMAMI}, base path "${BASE_PATH || '/'}"`);
  // After listen, so a slow or unreachable authz cannot delay readiness.
  registerRoutes();
});
