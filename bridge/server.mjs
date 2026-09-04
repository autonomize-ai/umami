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
 * So the line is drawn here instead, and only around the two calls that
 * destroy a website's data:
 *
 *   DELETE /api/websites/{id}   removes the site
 *   POST   /api/websites/{id}/reset   erases its events
 *
 * Deleting a site is worse than losing history. The site id is what the
 * tracker posts events to, and it is DERIVED (a hash of the environment host
 * plus the chart name), not stored -- so the provisioning job recreates the
 * same id on the next deploy, empty. Ingestion silently resumes into a blank
 * site, the dashboard still loads, and the charts just start from zero. There
 * is no error to notice and nothing to restore.
 *
 * Nobody's job requires either call: sites are created and maintained by
 * automation, never by hand. A human reaching them is always a mistake.
 *
 * A denylist is normally the weaker pattern, but the surface here is two fixed
 * endpoints in a third-party API we do not control, so enumerating them is
 * both tractable and easier to review than the alternative.
 */
const BLOCKED = (process.env.BRIDGE_BLOCKED_CALLS ||
  'DELETE:^/api/websites/[^/]+/?$,POST:^/api/websites/[^/]+/reset/?$')
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
  const token = await getServiceToken();

  const res = await fetch(`${UMAMI}${BASE_PATH}/api/auth/sso`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  });

  if (res.status === 401) {
    // The cached service token stopped working — the account's password was
    // rotated, or APP_SECRET changed. Drop it and let the next request retry
    // from a fresh login rather than failing for the life of the pod.
    serviceToken = null;
    throw new Error('service token rejected; cleared for retry');
  }

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
  const token = await getServiceToken();
  const auth = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

  const existing = await fetch(`${UMAMI}${BASE_PATH}/api/websites/${websiteId}`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (existing.status === 401) {
    // The cached token went stale; clear it so the next attempt re-logs in.
    serviceToken = null;
    throw new Error('service token rejected; cleared for retry');
  }

  if (existing.ok) {
    const body = await existing.json().catch(() => null);
    // A 200 with a null body is Umami's "not found" for this endpoint, so the
    // body is checked rather than the status alone.
    if (body?.id) return { created: false, websiteId: body.id };
  }

  const res = await fetch(`${UMAMI}${BASE_PATH}/api/websites`, {
    method: 'POST',
    headers: auth,
    body: JSON.stringify({ id: websiteId, name, domain }),
  });

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
  } catch {
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

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      // A provisioning body is three short fields; anything larger is a
      // mistake or an attack, and is refused before it is buffered.
      if (data.length > 4096) reject(new Error('body too large'));
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
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
    await handleProvision(req, res);
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
