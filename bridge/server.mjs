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

import { queryDatabaseConfig, withReadOnly } from './db.mjs';
import {
  DATA_TYPE_NAMES,
  QueryError,
  buildAggregateSql,
  buildEventsSql,
  buildNestedEventsSql,
  buildPropsSql,
  buildSchemaSql,
  buildSessionRowsSql,
  buildSessionsPageSql,
  parseQueryRequest,
  parseWindow,
  propsByOwner,
  shapeAggregate,
  shapeEvent,
  shapeSession,
  tablesFor,
} from './query.mjs';
import {
  derivePassword,
  orgIdFromTeamName,
  parsePlatformApps,
  parseRoles,
  siteIdFor,
  siteNameFor,
  teamNameFor,
  tenantUserIdFor,
  tenantUsernameFor,
} from './tenancy.mjs';

const PORT = Number(process.env.BRIDGE_PORT || 3001);
const UMAMI = (process.env.UMAMI_INTERNAL_URL || 'http://127.0.0.1:3000').replace(/\/$/, '');
const BASE_PATH = (process.env.BASE_PATH || '').replace(/\/$/, '');
const USERNAME = process.env.UMAMI_STAFF_USER || '';
const PASSWORD = process.env.UMAMI_STAFF_PASSWORD || '';
const ROLE_HEADER = 'x-user-roles';

/**
 * Roles admitted at the entry path, and which Umami account each one becomes.
 *
 * The gateway's requiredRoles is the real gate; this re-check is defence in
 * depth. It used to be ONE role (BRIDGE_REQUIRED_ROLE). With tenant sign-in the
 * gateway admits a second one, and a single-role re-check here would refuse
 * every tenant admin with a 403 the gateway had just let through -- so it is a
 * list now. BRIDGE_REQUIRED_ROLE is still read, for a chart that predates this.
 *
 *   STAFF_ROLE  -> the shared staff account (Umami `admin`): sees every site.
 *   TENANT_ROLE -> that org's own Umami user (`view-only` + `team-view-only`):
 *                  sees only the org's team.
 *
 * A caller holding both is signed in as staff. The staff account can see
 * everything the tenant account can, so choosing it never widens access.
 */
const REQUIRED_ROLES = parseRoles(
  process.env.BRIDGE_REQUIRED_ROLES || process.env.BRIDGE_REQUIRED_ROLE || 'platform-admin',
);
const STAFF_ROLE = process.env.BRIDGE_STAFF_ROLE || 'platform-admin';
const TENANT_ROLE = process.env.BRIDGE_TENANT_ROLE || 'tenant-admin';
const ORG_HEADER = 'x-organization-id';

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
 *
 * NO LONGER THE PRIMARY CONTROL. Reset is now refused by genesis-authz: the
 * bridge registers that path as a resource_pattern requiring
 * `umami_site can_reset`, a relation granted to nobody, so the gateway answers
 * 403 before this process is reached (see buildRoutePayload). This list stays
 * for two reasons -- it is defence in depth against a misregistered route, and
 * it is the operator knob for an environment that wants MORE refused than the
 * model does. Keep the two in step: something added here and nowhere else is
 * only enforced for callers that come through this proxy.
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
 * The prefix the app-facing READ API is published under -- and it is
 * deliberately NOT the prefix Umami itself is served from.
 *
 * WHY A SECOND PREFIX EXISTS AT ALL
 *
 * genesis-authz resolves a request by the KIND of registration that matches
 * its path, not by how specific the match is:
 *
 *   * `verify.py:1486` consults `_should_bypass_auth()` BEFORE it reaches the
 *     resource-pattern branch (~`verify.py:1753`), and a bypass short-circuits
 *     authorization entirely.
 *   * `verify.py:743-753` returns on the FIRST matching bypass regex. No
 *     priority comparison happens; `priority` only orders rows WITHIN one kind
 *     (`repositories/route_registration.py:47`).
 *
 * This process registers prefix-wide `bypass` rows for Umami's own tree,
 * because none of it is modelled in FGA and its gate is the gateway's
 * requiredRoles. Those rows match by segment COUNT, so any path under the
 * Umami prefix is covered by one of them -- including a per-site read. A
 * `resource_pattern` registered under that prefix is therefore never reached:
 * compiling these very rows with genesis-authz's own `compile_pattern` and
 * running its bypass loop verbatim, `/umami/query/{uuid}` matches
 * `^/umami/(?:[^/]+)/(?:[^/]+)/?$` and skips authorization altogether. The
 * read then SUCCEEDS -- one app reads another's numbers with a 200, and
 * nothing logs a refusal.
 *
 * The compiler cannot express the exclusion either: templates reject regex
 * metacharacters outright, so there is no way to say "any two segments except
 * query/{uuid}".
 *
 * So the read API moves out from under the bypassed prefix instead. Nothing is
 * registered under this one but the per-site rule itself, which means every
 * other path here default-denies -- the safe direction.
 *
 * Whoever fixes precedence in genesis-authz should NOT quietly fold this back
 * into the Umami prefix: the two are different surfaces, one third-party and
 * bypassed wholesale, one ours and authorized per site, and keeping them apart
 * is what makes that statement checkable.
 */
// Normalized to a non-empty prefix, so the path this process SERVES and the
// path it REGISTERS are the same string by construction. `/` would otherwise
// strip to '' and split the two apart -- registering /analytics while serving
// nothing -- which is the exact class of mismatch this whole constant exists
// to prevent.
const API_BASE_PATH =
  (process.env.BRIDGE_API_BASE_PATH || '/analytics').replace(/\/$/, '') || '/analytics';

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
 * Whether provisioning an EXISTING site records the caller as an owner.
 *
 * Off by default, because on it is a takeover: site ids are derived from host +
 * chart name, so any app holding a valid platform key could provision another
 * app's id, be recorded as an additional owner (ownership tuples are added, not
 * replaced) and then read that app's analytics through every per-site
 * endpoint. With it off, only the call that actually CREATES a site records an
 * owner, and that caller is by construction the app the id belongs to.
 *
 * It exists for one migration: sites created before ownership was recorded
 * (bridge releases before 2026-09-10) have no owner, and their apps get a 403
 * from every per-site endpoint until one is written. An environment upgrading
 * from such a release turns this on for one deploy, lets every app boot and
 * provision once, then turns it off again. genesis-authz offers no internal way
 * to ask "does this site already have an owner?", or this would decide per site.
 */
const PROVISION_ADOPT_EXISTING = process.env.BRIDGE_PROVISION_ADOPT_EXISTING === 'true';

/**
 * Where an app queries its OWN events, sessions and grouped counts, and where
 * it asks what event names and property keys its site holds.
 *
 * A NAMED endpoint, emphatically not a proxy onto Umami's API. Publishing
 * /api/websites/{id}/* to apps would hand every one of them most of the
 * dashboard API under a shared key -- including calls that MUTATE. What an app
 * can see is decided by query.mjs, and widening it is a deliberate edit there
 * rather than an accident of routing.
 *
 * `query` in `events` and `sessions` mode returns rows -- one per event, one per
 * session -- because an app reconstructing its own funnels and KPIs needs them,
 * and a fixed set of aggregates cannot anticipate every app's question. What
 * keeps that acceptable is that the columns that carry identifying text (page
 * titles, query strings, referrer paths, distinct_id, ad click ids) are not
 * selectable, filterable or groupable at all -- see query.mjs. Rows hold only
 * what the collector already scrubbed on the way in.
 *
 * Authorized per site: the site id is a path segment under API_BASE_PATH,
 * registered as a `resource_pattern` on `umami_site`, so /verify checks
 * `can_view` before this process is reached.
 *
 * Reads Postgres directly, read-only (see db.mjs), because Umami's REST API
 * cannot express these queries. A deployment that stores events in ClickHouse
 * instead is not served by this endpoint.
 */
const QUERY_PATH = process.env.BRIDGE_QUERY_PATH || '/query';
const SCHEMA_PATH = process.env.BRIDGE_SCHEMA_PATH || '/schema';

/**
 * Limits on what one query may return and how long it may run. There is no cap
 * on the window: a caller may ask for any range. What bounds the cost is the
 * statement timeout, which Postgres enforces, and the row limits below.
 */
const QUERY_LIMITS = {
  maxEventsPage: Number(process.env.BRIDGE_QUERY_MAX_EVENTS_PAGE || 1000),
  maxSessionsPage: Number(process.env.BRIDGE_QUERY_MAX_SESSIONS_PAGE || 200),
  maxAggregateRows: Number(process.env.BRIDGE_QUERY_MAX_AGGREGATE_ROWS || 10000),
};
const QUERY_TIMEOUT_MS = Number(process.env.BRIDGE_QUERY_STATEMENT_TIMEOUT_MS || 30000);
const QUERY_POOL_MAX = Number(process.env.BRIDGE_QUERY_POOL_MAX || 4);
/** Matching events nested under one session when `include_events` is set. */
const QUERY_NESTED_EVENTS_MAX = Number(process.env.BRIDGE_QUERY_NESTED_EVENTS_MAX || 100);
/** Entries per list in a schema response. */
const SCHEMA_LIST_MAX = Number(process.env.BRIDGE_SCHEMA_LIST_MAX || 1000);
const QUERY_DB = queryDatabaseConfig();
// A bad schema name disables the query API rather than the whole bridge.
const QUERY_TABLES = (() => {
  try {
    return QUERY_DB ? tablesFor(QUERY_DB.schema) : null;
  } catch (err) {
    console.log('[bridge]', 'query API disabled --', err.message);
    return null;
  }
})();

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
 * `bypass` is the right kind for Umami's own tree: it means "skip the OpenFGA
 * resource check, still require authentication". There is no Umami resource
 * modelled in FGA, and the authorization for that tree is the gateway's
 * requiredRoles gate.
 *
 * The app-facing read API is the exception, and it is registered under a
 * DIFFERENT prefix so a bypass row cannot swallow it -- see API_BASE_PATH,
 * which is the one thing to read before editing anything below.
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
  const apiPrefix = API_BASE_PATH;
  const routes = [];

  // THE ROUTES THAT ARE AUTHORIZED PER RESOURCE: the query API.
  //
  // Registered under apiPrefix, NOT prefix. The bypass rows below match by
  // segment count, so a resource_pattern under the Umami prefix is shadowed by
  // one of them and never runs -- genesis-authz checks bypass BEFORE resource
  // patterns and compares no priority across kinds. See API_BASE_PATH for the
  // mechanism and the proof. Priority is still set below, but it orders rows
  // only within a kind; it is not what keeps this rule alive. Being outside
  // the bypassed prefix is.
  //
  // `resource_pattern` makes /verify check `umami_site can_view` on the id it
  // captures from the path, against the tuple registerSiteOwnership() wrote.
  // The check therefore happens at the GATEWAY, before this process is reached
  // -- an app asking for a site it does not own is refused upstream, and this
  // handler needs no authorization code of its own.
  //
  // This is why the site id is a path segment: every URI matcher in
  // genesis-authz strips the query string before matching, so `?site=<uuid>`
  // would leave the rule with no object to check.
  //
  // `resource_pattern` derives the action from the HTTP method. `schema` is a
  // GET, so it resolves to can_view on its own. `query` is a POST, so it NEEDS
  // action_override: POST would resolve to can_create, which is not a relation
  // on umami_site. It only reads, so it asks can_view.
  //
  // Ordered first and given the lowest priority number for legibility -- the
  // rules that authorize per site should read first. What actually protects
  // them from the catch-all is the prefix, not the number.
  routes.push({
    kind: 'resource_pattern',
    pattern_template: `${apiPrefix}${QUERY_PATH}/{siteId}`,
    resource_type: 'umami_site',
    id_param: 'siteId',
    params: [{ name: 'siteId', type: 'uuid' }],
    action_override: 'can_view',
    priority: 10,
  });
  routes.push({
    kind: 'resource_pattern',
    pattern_template: `${apiPrefix}${SCHEMA_PATH}/{siteId}`,
    resource_type: 'umami_site',
    id_param: 'siteId',
    params: [{ name: 'siteId', type: 'uuid' }],
    priority: 10,
  });

  // Reset, expressed as a permission -- and INERT TODAY. Read this before
  // relying on it.
  //
  // This row sits under the Umami prefix and is shadowed by the catch-all
  // bypass below exactly as the query rows would be under it (the depth-4 one,
  // `^/umami/(?:[^/]+)/(?:[^/]+)/(?:[^/]+)/(?:[^/]+)/?$`). So the `can_reset`
  // check does NOT run, and the live control is the denylist above.
  //
  // Unlike the query API, it cannot be moved out of the way: this is Umami's OWN
  // API path, called by the dashboard in a browser. Changing it would mean
  // patching third-party code.
  //
  // It is registered anyway, for two reasons. It costs one row, and it is the
  // correct rule -- so when precedence in genesis-authz is fixed (a wide
  // bypass should not shadow a narrow resource_pattern; see API_BASE_PATH) this
  // becomes the gate with no change here. Until then the honest description is:
  // BRIDGE_BLOCKED_CALLS refuses reset, and this row documents who should be
  // allowed to when someone can ask that question properly.
  //
  // The relation is deliberately NOT derived from `owner` -- an app owns its
  // site so it can provision and read it, never so it can erase it -- and it
  // admits `user` only, so an app cannot be granted it even by mistake.
  //
  // Expressed as a permission rather than a refusal because it makes the answer
  // changeable: if staff ever need to reset a test site, someone writes one
  // tuple in genesis-authz instead of editing BRIDGE_BLOCKED_CALLS and
  // redeploying Umami.
  //
  // action_override is required. The method here is POST, which would otherwise
  // resolve to can_create by the method->action default, and can_create is not
  // a relation on this type.
  routes.push({
    kind: 'resource_pattern',
    pattern_template: `${prefix}/api/websites/{siteId}/reset`,
    resource_type: 'umami_site',
    id_param: 'siteId',
    params: [{ name: 'siteId', type: 'uuid' }],
    action_override: 'can_reset',
    priority: 10,
  });

  // Provisioning stays authenticated-only: the caller is creating its OWN site
  // from an id it computed itself, so there is no existing resource to check a
  // permission against. What bounds it instead is that the call only ever
  // creates, and that the ownership tuple is written from the gateway-stamped
  // identity rather than from anything in the body.
  routes.push({ kind: 'bypass', pattern_template: `${prefix}/provision`, params: [], priority: 20 });

  // Everything else -- the dashboard, its assets, Umami's own API behind the
  // browser session -- stays as it was: authenticated by the gateway, with the
  // role decision made by the route's requiredRoles rather than per resource.
  // There is no Umami resource modelled in FGA for those, and the dashboard is
  // staff-only, so a bypass is honest about what is actually enforced.
  //
  // Still one row per depth, because the widest param type matches a single
  // segment and Umami's own tree reaches six levels below the prefix.
  //
  // These rows are why the query API's rules live under apiPrefix. Widening them
  // does NOT stay clear of a resource_pattern on the same prefix: bypass is
  // checked first and no priority is compared across kinds, so a row here
  // silently turns off any per-resource check under this prefix. That is
  // already true of the reset row above. Anything that must be authorized per
  // resource belongs outside this prefix.
  routes.push({ kind: 'bypass', pattern_template: prefix, params: [], priority: 100 });
  for (let depth = 1; depth <= ROUTE_MAX_DEPTH; depth++) {
    const names = Array.from({ length: depth }, (_, i) => `s${i}`);
    routes.push({
      kind: 'bypass',
      pattern_template: `${prefix}/${names.map(n => `{${n}}`).join('/')}`,
      // `any` is one path segment. Segment count is what the depth expresses.
      params: names.map(name => ({ name, type: 'any' })),
      priority: 100,
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
      log(
        `registered ${ROUTE_MAX_DEPTH + 5} route patterns with genesis-authz ` +
          '(query, schema + reset authorized per site, provision authenticated, ' +
          'rest bypass)',
      );
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
 * Record who owns an analytics site, in genesis-authz.
 *
 * WHY THIS EXISTS
 *
 * Without it this endpoint set has no ownership at all: an app that knows
 * another app's site id can read its numbers, and ids are derived from host +
 * chart name, so they are guessable. One tuple per site closes that, and it
 * closes BOTH boundaries at once -- cross-org and, more strictly, two sibling
 * apps inside one organization.
 *
 * WHY THE OWNER IS THE SERVICE ACCOUNT AND NOT THE ORG
 *
 * Two siblings share an organization, so an org-level record cannot separate
 * them. The service account can: the gateway resolves the caller's API key and
 * stamps X-User-Id, so the identity recorded here is one the app cannot choose.
 * It requires one service account per app -- if two apps share a key they are
 * one identity to the platform and no record here can tell them apart.
 *
 * The org is recorded as the parent anyway. It enforces nothing for apps (no
 * service account is a tenant admin) and exists so a customer's org admin can
 * later read every site in their own org through `tenant_admin from
 * organization` in the model, with no per-site tuple ever written.
 *
 * NEVER FATAL. A site whose tuple could not be written is readable by nobody
 * once the check is enforced, which is the safe direction to fail -- but it
 * must not take down the provisioning call that an app makes at boot.
 */
async function registerSiteOwnership(websiteId, ownerId, organizationId) {
  if (!AUTHZ_URL || !AUTHZ_KEY) {
    log('ownership: not recorded -- AUTHZ_INTERNAL_URL/KEY not set');
    return false;
  }
  if (!ownerId) {
    // The gateway stamps X-User-Id after resolving the caller's credential, so
    // an absent one means this request did not come through the gateway. Worth
    // saying plainly: it is the difference between "unowned" and "misrouted".
    log('ownership: not recorded for', websiteId, '-- no X-User-Id on the request');
    return false;
  }

  try {
    const res = await fetch(`${AUTHZ_URL}/internal/authz/register-resource`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Internal-Call': AUTHZ_KEY },
      body: JSON.stringify({
        resource_type: 'umami_site',
        resource_id: websiteId,
        owner_type: 'service_account',
        owner_id: ownerId,
        ...(organizationId
          ? { parent_type: 'organization', parent_id: organizationId }
          : {}),
      }),
    });
    if (res.ok) {
      log('ownership: site', websiteId, 'owned by service_account', ownerId);
      return true;
    }
    const detail = await res.text().catch(() => '');
    log(`ownership: register failed ${res.status} ${detail.slice(0, 200)}`);
    return false;
  } catch (err) {
    log('ownership: register failed --', err.message);
    return false;
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

/** The roles the gateway stamped on this request (never client-supplied). */
function callerRoles(req) {
  return parseRoles(req.headers[ROLE_HEADER]);
}

function hasRequiredRole(req) {
  const held = callerRoles(req);
  return REQUIRED_ROLES.some(role => held.includes(role));
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

/**
 * Strip the app-facing API prefix, the counterpart to appPath() above.
 *
 * Separate because the two prefixes mean different things: BASE_PATH is where
 * third-party Umami is mounted, API_BASE_PATH is where this bridge answers for
 * itself. See API_BASE_PATH for why they cannot be the same string.
 */
function apiPath(pathname) {
  return pathname.startsWith(API_BASE_PATH)
    ? pathname.slice(API_BASE_PATH.length) || '/'
    : null;
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
 * Match {endpoint}/{siteId} under API_BASE_PATH and return the site id, or null.
 *
 * THE SITE ID IS A PATH SEGMENT, NOT A QUERY PARAMETER, AND THAT IS LOAD-BEARING.
 *
 * genesis-authz authorizes a request by mapping its PATH to a permission, and
 * every URI matcher on that side strips the query string before matching. So
 * `?site=<uuid>` gives the authorization rule no object to check -- the site id
 * has to be in the path for a per-site permission to be expressible at all.
 * It is the reason these routes can be registered as a `resource_pattern`
 * rather than a `bypass` (see buildRoutePayload).
 *
 * Matched under API_BASE_PATH, not BASE_PATH: a `resource_pattern` under the
 * Umami prefix is shadowed by the bypass rows registered for that tree and
 * never runs. See API_BASE_PATH for the proof.
 *
 * The bare collection path is deliberately NOT matched: /query with no id
 * would have to mean "every site", which is the one thing these endpoints must
 * never answer.
 */
function apiSiteId(pathname, endpoint) {
  const stripped = apiPath(pathname);
  if (!stripped || !stripped.startsWith(`${endpoint}/`)) return null;
  const rest = stripped.slice(endpoint.length + 1);
  // One segment only. A deeper path is a different endpoint, not this one with
  // a suffix, and letting it match here would make `/query/{id}/anything`
  // silently return the site's numbers.
  return rest && !rest.includes('/') ? rest : null;
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

  // The derive form: the caller names its app ({ chart }) and this process
  // works out the per-organisation site id. The original form below, where an
  // app sends a pre-computed id, is unchanged -- marketplace apps use it.
  if (payload && payload.websiteId === undefined && payload.chart !== undefined) {
    await handleProvisionForOrg(req, res, String(payload.chart));
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

  // Stamped by the gateway from the caller's own credential, after it clears
  // any copy the client tried to send. So this is the one identity in the
  // request the app cannot choose for itself -- which is what makes it usable
  // as an ownership record.
  const ownerId = req.headers['x-user-id'] || '';
  const organizationId = req.headers['x-organization-id'] || '';

  try {
    const result = await provisionSite({ websiteId, name, domain });
    log('provision', result.created ? 'created' : 'already present', websiteId, name);

    // Recorded when this call CREATED the site, and not otherwise -- see
    // PROVISION_ADOPT_EXISTING. This used to run on every call so that sites
    // predating ownership would adopt an owner, but register-resource ADDS an
    // owner rather than replacing one, so it also let any app make itself a
    // co-owner of any other app's site. Adoption is now an explicit, temporary
    // switch for that migration instead.
    //
    // Retried a few times on create, because there is no second chance: the
    // next boot finds the site present and leaves ownership alone.
    let owned = false;
    if (result.created || PROVISION_ADOPT_EXISTING) {
      const attempts = result.created ? 3 : 1;
      for (let i = 1; i <= attempts && !owned; i++) {
        owned = await registerSiteOwnership(websiteId, ownerId, organizationId);
        if (!owned && i < attempts) await new Promise(r => setTimeout(r, 1000 * i));
      }
      if (!owned && result.created) {
        log(
          'provision: site',
          websiteId,
          'was created but has NO owner recorded; its app will get 403s ' +
            'from the per-site endpoints until an owner is written (BRIDGE_PROVISION_ADOPT_EXISTING).',
        );
      }
    }

    res.writeHead(result.created ? 201 : 200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ...result, ownershipRecorded: owned }));
  } catch (err) {
    // 502, not 500: the failure is upstream in Umami, and the caller is a
    // deploy-time script that should log and carry on rather than crash.
    log('provision failed', websiteId, '--', err.message);
    deny(res, 502, 'Could not provision the analytics site.');
  }
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
 * Run one query-API read and translate its failure into a status.
 *
 * Validation failures carry their own 400/422. Postgres cancelling a statement
 * for running past the timeout (SQLSTATE 57014) is a 504 the caller can act on
 * by narrowing the window. Everything else is logged in full and answered
 * generically, so no SQL or schema detail reaches an app.
 */
async function answerQuery(res, site, label, read) {
  try {
    const body = await withReadOnly(QUERY_TABLES && QUERY_DB, read, {
      timeoutMs: QUERY_TIMEOUT_MS,
      poolMax: QUERY_POOL_MAX,
      log,
    });
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify({ api_version: '1', site_id: site, ...body }));
  } catch (err) {
    denyQueryFailure(res, site, label, err);
  }
}

/** Answer a failed query-API read with a status, never with SQL or schema detail. */
function denyQueryFailure(res, site, label, err) {
  if (err instanceof QueryError) {
    deny(res, err.status, err.message);
  } else if (err.code === '57014') {
    log(label, 'timed out for', site);
    deny(
      res,
      504,
      `The query ran past ${QUERY_TIMEOUT_MS / 1000}s. Narrow the window or the filters.`,
    );
  } else if (err.status === 503) {
    deny(res, 503, 'The analytics query API is not available right now.');
  } else {
    log(label, 'failed for', site, '--', err.message);
    deny(res, 502, 'Could not read analytics for that site.');
  }
}

const isoWindow = w => ({ from: w.from.toISOString(), to: w.to.toISOString() });

/**
 * POST {API_BASE_PATH}/query/{siteId} -- events, sessions or grouped counts for
 * one site, per a structured JSON body. See query.mjs for the request grammar
 * and QUERY_PATH for what it deliberately can and cannot return.
 */
async function handleQuery(req, res, site) {
  if ((req.method || '').toUpperCase() !== 'POST') {
    deny(res, 405, 'Use POST to query analytics.');
    return;
  }
  if (!UUID_RE.test(site)) {
    deny(res, 400, 'The site id in the path must be a uuid.');
    return;
  }

  let spec;
  try {
    const raw = await readBody(req, MAX_QUERY_BODY_BYTES);
    let body;
    try {
      body = JSON.parse(raw);
    } catch {
      throw new QueryError(400, 'The request body must be JSON.');
    }
    spec = parseQueryRequest(body, QUERY_LIMITS);
  } catch (err) {
    if (err?.tooLarge) {
      deny(res, 413, `Request body is larger than ${MAX_QUERY_BODY_BYTES} bytes.`);
      req.destroy();
      return;
    }
    if (err instanceof QueryError) {
      deny(res, err.status, err.message);
      return;
    }
    throw err;
  }

  const t = QUERY_TABLES;
  await answerQuery(res, site, `query(${spec.mode})`, async client => {
    const head = { mode: spec.mode, window: isoWindow(spec.window) };

    if (spec.mode === 'aggregate') {
      const { text, values } = buildAggregateSql(spec, site, t);
      const { rows } = await client.query(text, values);
      const shaped = shapeAggregate(spec, rows);
      if (spec.includeTotal && !rows.length && spec.offset) {
        // Past the last row: nothing carried the total, so ask for row one.
        const q = buildAggregateSql({ ...spec, offset: 0, limit: 1 }, site, t);
        const again = (await client.query(q.text, q.values)).rows;
        shaped.total = again.length ? Number(again[0].total_count) : 0;
      } else if (spec.includeTotal && !rows.length) {
        shaped.total = 0;
      }
      return { ...head, of: spec.scope, timezone: spec.timezone, ...shaped };
    }

    const pageOut = { number: spec.page.number, size: spec.page.size };

    if (spec.mode === 'events') {
      const q = buildEventsSql(spec, site, t);
      const { rows } = await client.query(q.text, q.values);
      const page = rows.slice(0, spec.page.size);
      let props = null;
      if (!spec.eventProps.none && page.length) {
        const pq = buildPropsSql(
          'event',
          site,
          page.map(r => r.event_id),
          spec.eventProps,
          t,
        );
        props = propsByOwner((await client.query(pq.text, pq.values)).rows);
      }
      let sessionProps = null;
      if (!spec.sessionProps.none && page.length) {
        const ids = [...new Set(page.map(r => r.session_id))];
        const sq = buildPropsSql('session', site, ids, spec.sessionProps, t);
        sessionProps = propsByOwner((await client.query(sq.text, sq.values)).rows);
      }
      return {
        ...head,
        events: page.map(r => {
          const out = shapeEvent(r, spec.eventFields, props && (props.get(r.event_id) || {}));
          if (sessionProps) out.session_props = sessionProps.get(r.session_id) || {};
          return out;
        }),
        page: {
          ...pageOut,
          returned: page.length,
          has_more: rows.length > spec.page.size,
          ...(spec.includeTotal
            ? { total: await totalOf(client, rows, buildEventsSql, spec, site) }
            : {}),
        },
      };
    }

    // sessions
    const pageQuery = buildSessionsPageSql(spec, site, t);
    const { rows } = await client.query(pageQuery.text, pageQuery.values);
    const page = rows.slice(0, spec.page.size);
    const ids = page.map(r => r.session_id);
    const sessions = new Map();
    let sessionProps = null;
    let nested = null;
    if (ids.length) {
      const s = buildSessionRowsSql(site, ids, t);
      for (const row of (await client.query(s.text, s.values)).rows)
        sessions.set(row.session_id, row);
      if (!spec.sessionProps.none) {
        const q = buildPropsSql('session', site, ids, spec.sessionProps, t);
        sessionProps = propsByOwner((await client.query(q.text, q.values)).rows);
      }
      if (spec.includeEvents) {
        const n = buildNestedEventsSql(spec, site, ids, QUERY_NESTED_EVENTS_MAX, t);
        const eventRows = (await client.query(n.text, n.values)).rows;
        let eventProps = null;
        if (!spec.eventProps.none && eventRows.length) {
          const q = buildPropsSql(
            'event',
            site,
            eventRows.map(r => r.event_id),
            spec.eventProps,
            t,
          );
          eventProps = propsByOwner((await client.query(q.text, q.values)).rows);
        }
        nested = new Map();
        for (const r of eventRows) {
          if (!nested.has(r.session_id)) nested.set(r.session_id, []);
          nested
            .get(r.session_id)
            .push(
              shapeEvent(r, spec.eventFields, eventProps && (eventProps.get(r.event_id) || {})),
            );
        }
      }
    }

    return {
      ...head,
      sessions: page.map(p => {
        // A session row can be missing only if Umami deleted it mid-request;
        // the page row still says which session it was.
        const out = shapeSession(
          sessions.get(p.session_id) || { session_id: p.session_id },
          p,
          spec.sessionFields,
        );
        if (sessionProps) out.props = sessionProps.get(p.session_id) || {};
        if (nested) {
          const events = nested.get(p.session_id) || [];
          out.events = events.slice(0, QUERY_NESTED_EVENTS_MAX);
          if (events.length > QUERY_NESTED_EVENTS_MAX) out.events_truncated = true;
        }
        return out;
      }),
      page: {
        ...pageOut,
        returned: page.length,
        has_more: rows.length > spec.page.size,
        ...(spec.includeTotal
          ? { total: await totalOf(client, rows, buildSessionsPageSql, spec, site) }
          : {}),
      },
    };
  });
}

/**
 * The total behind a page. Every row carries it (COUNT(*) OVER ()), so it is
 * free -- except on a page past the end, which has no rows to carry it; that
 * one case asks again for the first row.
 */
async function totalOf(client, rows, build, spec, site) {
  if (rows.length) return Number(rows[0].total_count);
  if (spec.page.number === 1) return 0;
  const q = build({ ...spec, page: { number: 1, size: 1 } }, site, QUERY_TABLES);
  const again = (await client.query(q.text, q.values)).rows;
  return again.length ? Number(again[0].total_count) : 0;
}

/**
 * GET {API_BASE_PATH}/schema/{siteId}?from=&to= -- the event names, event
 * property keys and session property keys a site holds in a window, with each
 * key's stored type, so a caller can build a query without guessing names.
 */
async function handleSchema(req, res, site) {
  if ((req.method || '').toUpperCase() !== 'GET') {
    deny(res, 405, 'Use GET to read an analytics schema.');
    return;
  }
  if (!UUID_RE.test(site)) {
    deny(res, 400, 'The site id in the path must be a uuid.');
    return;
  }
  const params = new URL(req.url, 'http://localhost').searchParams;
  for (const key of params.keys()) {
    if (key !== 'from' && key !== 'to') {
      deny(res, 400, `Unknown query parameter "${key}". Allowed: from, to.`);
      return;
    }
  }
  let window;
  try {
    window = parseWindow(params.get('from'), params.get('to'), '');
  } catch (err) {
    deny(res, err.status || 400, err.message);
    return;
  }

  await answerQuery(res, site, 'schema', async client => {
    const q = buildSchemaSql(site, window, SCHEMA_LIST_MAX, QUERY_TABLES);
    const [events, eventKeys, eventProps, sessionProps] = [
      (await client.query(q.events.text, q.events.values)).rows,
      (await client.query(q.eventKeys.text, q.eventKeys.values)).rows,
      (await client.query(q.eventProps.text, q.eventProps.values)).rows,
      (await client.query(q.sessionProps.text, q.sessionProps.values)).rows,
    ];
    const keysByEvent = new Map();
    for (const { name, key } of eventKeys) {
      if (!keysByEvent.has(name)) keysByEvent.set(name, []);
      keysByEvent.get(name).push(key);
    }
    const typed = rows =>
      rows.slice(0, SCHEMA_LIST_MAX).map(r => ({
        key: r.key,
        type: DATA_TYPE_NAMES[r.type] || String(r.type),
      }));
    const body = {
      window: isoWindow(window),
      events: events.slice(0, SCHEMA_LIST_MAX).map(r => ({
        name: r.name,
        count: Number(r.count),
        last_at: r.last_at instanceof Date ? r.last_at.toISOString() : r.last_at,
        props: keysByEvent.get(r.name) || [],
      })),
      event_props: typed(eventProps),
      session_props: typed(sessionProps),
    };
    const cut = [
      ['events', events],
      ['event_props', eventProps],
      ['session_props', sessionProps],
    ]
      .filter(([, rows]) => rows.length > SCHEMA_LIST_MAX)
      .map(([name]) => name);
    if (cut.length) body.truncated = cut;
    return body;
  });
}

/**
 * A provisioning body is three short fields. Anything larger is a mistake or an
 * attack, and this endpoint is reachable by every app on the platform.
 */
const MAX_BODY_BYTES = 4096;

/**
 * A query body carries filters and lists, so it gets more room than a
 * provisioning body -- but still a fixed ceiling, for the same reason.
 */
const MAX_QUERY_BODY_BYTES = 65536;

function readBody(req, limit = MAX_BODY_BYTES) {
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
      if (data.length > limit) stop(Object.assign(new Error('body too large'), { tooLarge: true }));
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

// ===========================================================================
// TENANT ISOLATION
// ===========================================================================
//
// One Umami team per organisation, one website per platform app inside it, and
// a tenant admin signed in as their org's own restricted user. Umami enforces
// the walls itself -- src/permissions/website.ts canViewWebsite makes a
// team-owned site visible only to that team's members -- so everything below
// only keeps the teams, sites and memberships in place and hands out the right
// session.
//
// Two independent switches, both default-off:
//
//   BRIDGE_RECONCILE_ENABLED     the background loop that creates teams and
//                                sites for every org, and the derive-the-id
//                                form of /provision
//   BRIDGE_TENANT_SIGNIN_ENABLED signing a tenant admin in as their org's user
//
// Neither exposes anything on its own. A tenant admin reaches this process only
// once the gateway's umami-dashboard route admits their role, which is a
// separate, deliberate change made last.

/**
 * Reconciler configuration. A problem here DISABLES the reconciler with a loud
 * log line rather than crashing the sidecar: this process also serves the
 * existing staff sign-in, and a typo in a new setting must not take that down.
 */
const RECONCILE = (() => {
  const cfg = {
    enabled: process.env.BRIDGE_RECONCILE_ENABLED === 'true',
    host: (process.env.BRIDGE_PLATFORM_HOST || '').trim(),
    apps: [],
    // How long one org-list call may be held open by authz waiting for a change.
    waitSeconds: Number(process.env.BRIDGE_RECONCILE_POLL_SECONDS || 30),
    // MUST exceed waitSeconds: authz deliberately holds the call that long, so a
    // shorter client timeout fires first and every long-poll fails -- the loop
    // keeps "running" while learning nothing. genesis-provisioner documents the
    // same trap next to its own requestTimeoutSeconds.
    requestTimeoutMs: Number(process.env.BRIDGE_RECONCILE_REQUEST_TIMEOUT_SECONDS || 45) * 1000,
    // Floor between ticks. An authz that ignores `wait` answers instantly, and
    // without this the loop would spin against authz and Umami as fast as they
    // could answer. A real change still gets picked up within this long.
    minIntervalMs: Number(process.env.BRIDGE_RECONCILE_MIN_INTERVAL_SECONDS || 5) * 1000,
    // Which org-list field is the org id. The authz list carries BOTH `id` and
    // `keycloak_id`, and they differ; this must be the one the gateway stamps as
    // X-Organization-Id, or apps and this loop compute different site ids for
    // the same org. keycloak_id is the default because the platform's tenant
    // roles are minted from it and the apps' own sessions read the Keycloak
    // `organization` claim. CONFIRM against a live /verify response.
    orgIdField: process.env.BRIDGE_RECONCILE_ORG_ID_FIELD || 'keycloak_id',
    problems: [],
  };

  try {
    cfg.apps = parsePlatformApps(process.env.BRIDGE_PLATFORM_APPS);
  } catch (err) {
    cfg.problems.push(err.message);
  }
  if (!cfg.host) cfg.problems.push('BRIDGE_PLATFORM_HOST is empty');
  // A bare host only. A scheme or path is a different hash, so a different
  // site from the one every app computes -- silently.
  if (cfg.host.includes('/')) cfg.problems.push(`BRIDGE_PLATFORM_HOST must be a bare host, got "${cfg.host}"`);
  if (!cfg.apps.length) cfg.problems.push('BRIDGE_PLATFORM_APPS lists no apps');

  // Deriving a site id needs only the host and the app list; the loop also
  // needs authz.
  cfg.deriveReady = cfg.problems.length === 0;

  if (cfg.enabled) {
    const loopProblems = [...cfg.problems];
    if (!AUTHZ_URL || !AUTHZ_KEY) loopProblems.push('AUTHZ_INTERNAL_URL/KEY are not set');
    if (!(cfg.requestTimeoutMs > cfg.waitSeconds * 1000)) {
      loopProblems.push(
        `request timeout (${cfg.requestTimeoutMs / 1000}s) must exceed the poll wait (${cfg.waitSeconds}s)`,
      );
    }
    if (loopProblems.length) {
      log('reconcile DISABLED --', loopProblems.join('; '));
      cfg.enabled = false;
    }
  }
  return cfg;
})();

const TENANT_SIGNIN = (() => {
  const cfg = {
    enabled: process.env.BRIDGE_TENANT_SIGNIN_ENABLED === 'true',
    // The key tenant-user passwords are derived from. Never sent anywhere.
    secret: process.env.BRIDGE_TENANT_PASSWORD_SECRET || '',
  };
  if (cfg.enabled && !cfg.secret) {
    log('tenant sign-in DISABLED -- BRIDGE_TENANT_PASSWORD_SECRET is empty');
    cfg.enabled = false;
  }
  return cfg;
})();

/** A refusal we chose, as opposed to an upstream failure -- answered with 403. */
function refuse(message) {
  return Object.assign(new Error(message), { status: 403 });
}

/** A mutating call against Umami's admin API, as the staff account. */
async function umamiSend(method, path, body) {
  const res = await withServiceToken(token =>
    fetch(`${UMAMI}${BASE_PATH}${path}`, {
      method,
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  );
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`${method} ${path.split('?')[0]} returned ${res.status} ${detail.slice(0, 160)}`);
  }
  return res.json().catch(() => null);
}

/**
 * Every row of one of Umami's paged listings.
 *
 * Paging is not optional. The staff-setup script lists teams with a single
 * `pageSize=200` call; past 200 organisations that silently stops finding a
 * team and the caller creates a DUPLICATE, with nothing failing anywhere.
 */
const UMAMI_PAGE_SIZE = 200;

async function umamiListAll(path) {
  const rows = [];
  for (let page = 1; ; page++) {
    const sep = path.includes('?') ? '&' : '?';
    const body = await umamiGet(`${path}${sep}page=${page}&pageSize=${UMAMI_PAGE_SIZE}`);
    const data = Array.isArray(body) ? body : body?.data || [];
    rows.push(...data);
    const total = Number(body?.count ?? rows.length);
    if (!data.length || rows.length >= total || data.length < UMAMI_PAGE_SIZE) break;
    if (page >= 1000) throw new Error(`${path}: stopped paging at ${rows.length} rows`);
  }
  return rows;
}

// --- organisations ---------------------------------------------------------

/** org id -> display name, filled from the org list. Names are cosmetic. */
const orgNames = new Map();
let orgNamesFetchedAt = 0;

/**
 * Every active organisation, from genesis-authz.
 *
 * `wait` makes the first page a long-poll: authz holds the call until an
 * organisations row changes (Postgres LISTEN/NOTIFY on `orgs_changed`) or the
 * wait runs out, and only THEN reads the table. So one call means "wait for a
 * change, then give me the full list" -- never a diff. Later pages use wait=0;
 * the change, if any, has already happened.
 */
const ORG_PAGE_SIZE = 1000;

async function fetchOrgs(waitSeconds) {
  const orgs = [];
  let unusable = 0;
  for (let skip = 0; ; skip += ORG_PAGE_SIZE) {
    const wait = skip === 0 ? waitSeconds : 0;
    const url =
      `${AUTHZ_URL}/internal/authz/platform/organizations` +
      `?active_only=true&skip=${skip}&limit=${ORG_PAGE_SIZE}&wait=${wait}`;
    const res = await fetch(url, {
      headers: { 'X-Internal-Call': AUTHZ_KEY },
      signal: AbortSignal.timeout(wait ? RECONCILE.requestTimeoutMs : 10000),
    });
    if (!res.ok) throw new Error(`org list returned ${res.status}`);
    const page = await res.json();
    if (!Array.isArray(page)) throw new Error('org list is not an array');
    for (const org of page) {
      const id = String(org?.[RECONCILE.orgIdField] || '').toLowerCase();
      if (!UUID_RE.test(id)) {
        unusable++;
        continue;
      }
      orgs.push({ id, name: String(org?.name || '').trim() });
    }
    if (page.length < ORG_PAGE_SIZE) break;
  }
  if (unusable) log(`orgs: ${unusable} org(s) had no usable ${RECONCILE.orgIdField}; skipped`);
  for (const org of orgs) orgNames.set(org.id, org.name);
  orgNamesFetchedAt = Date.now();
  return orgs;
}

/**
 * The display name for one org, looked up on a miss at most once a minute.
 * An empty name is fine: the team is then named by its id alone, and the
 * reconciler renames it once the name is known.
 */
async function orgNameFor(orgId) {
  if (orgNames.has(orgId)) return orgNames.get(orgId);
  if (AUTHZ_URL && AUTHZ_KEY && Date.now() - orgNamesFetchedAt > 60000) {
    orgNamesFetchedAt = Date.now();
    try {
      await fetchOrgs(0);
    } catch (err) {
      log('orgs: name lookup failed --', err.message);
    }
  }
  return orgNames.get(orgId) || '';
}

// --- teams -----------------------------------------------------------------

/** org id -> { id, name } of that org's Umami team. */
const teamByOrg = new Map();
const inflightTeams = new Map();
const counters = { teamsCreated: 0, sitesCreated: 0, sitesMoved: 0 };

/**
 * Rebuild the org -> team index from Umami.
 *
 * /api/admin/teams, NOT /api/teams: the latter returns only the CALLER's teams.
 * It happens to find every team today only because Umami makes whoever creates
 * a team its team-owner -- a side effect this must not depend on.
 */
async function refreshTeamIndex() {
  const teams = (await umamiListAll('/api/admin/teams')).filter(t => !t.deletedAt);
  // Oldest first, so a duplicate left by some past race never displaces the
  // original team -- and the one its sites are already in.
  teams.sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)));
  const next = new Map();
  const extra = new Map();
  for (const team of teams) {
    const orgId = orgIdFromTeamName(team.name);
    if (!orgId) continue;
    if (next.has(orgId)) {
      extra.set(orgId, (extra.get(orgId) || 1) + 1);
      continue;
    }
    next.set(orgId, { id: team.id, name: team.name });
  }
  for (const [orgId, n] of extra) {
    log(`teams: ${n} teams claim org ${orgId}; using the oldest. Remove the others by hand.`);
  }
  teamByOrg.clear();
  for (const [orgId, team] of next) teamByOrg.set(orgId, team);
}

/**
 * The org's team id, creating the team if it does not exist.
 *
 * SERIALISED PER ORG. Two callers seeing a brand-new org at once -- the
 * reconciler and a /provision call, say -- would both find no team and both
 * create one: two teams named for the same org, sites split between them, and
 * an admin who can see half. Umami has no uniqueness constraint on team names
 * to stop it. An in-process lock is enough ONLY because genesis-umami runs one
 * replica; scale that deployment and this needs a real lock.
 */
function ensureTeam(orgId, orgName, { indexFresh = false } = {}) {
  const known = teamByOrg.get(orgId);
  if (known) return Promise.resolve(known.id);
  if (inflightTeams.has(orgId)) return inflightTeams.get(orgId);

  const pending = (async () => {
    if (!indexFresh) {
      await refreshTeamIndex();
      const found = teamByOrg.get(orgId);
      if (found) return found.id;
    }
    const name = teamNameFor(orgName, orgId);
    const body = await umamiSend('POST', '/api/teams', { name });
    // POST /api/teams answers with createTeam's TRANSACTION result -- an array
    // of [team, ownerMembership], not a team -- so the team is the first entry.
    const team = Array.isArray(body) ? body[0] : body;
    if (!team?.id) throw new Error('team create returned no id');
    teamByOrg.set(orgId, { id: team.id, name });
    counters.teamsCreated++;
    log('team: created', JSON.stringify(name), team.id);
    return team.id;
  })().finally(() => inflightTeams.delete(orgId));

  inflightTeams.set(orgId, pending);
  return pending;
}

/** Keep the readable prefix in step with the org's current name. */
async function renameTeamIfNeeded(org, teamId) {
  if (!org.name) return;
  const current = teamByOrg.get(org.id);
  const desired = teamNameFor(org.name, org.id);
  if (!current || current.name === desired) return;
  await umamiSend('POST', `/api/teams/${teamId}`, { name: desired });
  teamByOrg.set(org.id, { id: teamId, name: desired });
  log('team: renamed', JSON.stringify(current.name), '->', JSON.stringify(desired));
}

// --- websites --------------------------------------------------------------

/**
 * Make sure one website exists, in the right place.
 *
 * `existing` is the row from an /api/admin/websites listing (or null when that
 * listing had no such site); leave it undefined to look the site up here.
 * Every site belongs to its org's team: there is no site outside a team.
 *
 * Created team-owned from the first moment: POST /api/websites sets userId only
 * when no teamId is given, and canViewWebsite returns on a set userId BEFORE it
 * ever looks at the team.
 */
async function ensureSite(siteId, name, teamId, existing) {
  if (!teamId) throw new Error(`site ${siteId}: every site belongs to an org's team`);
  let row = existing;
  if (row === undefined) {
    const body = await umamiGet(`/api/websites/${siteId}`);
    // A 200 with a null body is Umami's "not found" for this endpoint.
    row = body?.id ? body : null;
  }

  if (!row) {
    await umamiSend('POST', '/api/websites', { id: siteId, name, domain: RECONCILE.host, teamId });
    counters.sitesCreated++;
    log('site: created', siteId, JSON.stringify(name), `in team ${teamId}`);
    return 'created';
  }

  if (!row.teamId) {
    // Exists but owned by a user rather than a team (created by hand, say).
    // The team branch of canViewWebsite is never reached for it, so the team
    // would not see it. The transfer sets teamId and nulls userId in one write.
    await umamiSend('POST', `/api/websites/${siteId}/transfer`, { teamId });
    counters.sitesMoved++;
    log('site: moved into its team', siteId, teamId);
    return 'moved';
  }

  if (row.teamId !== teamId) {
    // Never moved between teams automatically: that is moving one tenant's
    // data to another, and nothing here can know which placement is right.
    log('site:', siteId, 'is in team', row.teamId, 'not', teamId, '-- left alone; check by hand');
    return 'mismatch';
  }
  return 'ok';
}

// --- the loop --------------------------------------------------------------

/**
 * One pass: every org gets a team, and every team one site per platform app.
 * Check-then-act throughout, so a pass over a healthy system changes nothing.
 */
async function reconcileOnce(orgs) {
  const before = { ...counters };
  await refreshTeamIndex();
  // One listing, not one lookup per site: 300 orgs x 3 apps would otherwise be
  // 900 calls against Umami every tick.
  const sites = new Map((await umamiListAll('/api/admin/websites')).map(w => [w.id, w]));
  const incomplete = [];

  for (const org of orgs) {
    try {
      const teamId = await ensureTeam(org.id, org.name, { indexFresh: true });
      await renameTeamIfNeeded(org, teamId);
      for (const app of RECONCILE.apps) {
        const siteId = siteIdFor(RECONCILE.host, app.chart, org.id);
        await ensureSite(siteId, siteNameFor(org.name, app.name), teamId, sites.get(siteId) || null);
      }
    } catch (err) {
      incomplete.push(org.id);
      log('reconcile: org', org.id, 'incomplete --', err.message);
    }
  }

  // Same shape as genesis-provisioner's `reconcile_once done: orgs=N`, so the
  // two read alike in logs. `incomplete` is the number to alert on: it is the
  // count of orgs that do NOT currently have a team holding every site.
  log(
    `reconcile_once done: orgs=${orgs.length}` +
      ` teams_created=${counters.teamsCreated - before.teamsCreated}` +
      ` sites_created=${counters.sitesCreated - before.sitesCreated}` +
      ` sites_moved=${counters.sitesMoved - before.sitesMoved}` +
      ` incomplete=${incomplete.length}` +
      (incomplete.length ? ` [${incomplete.slice(0, 10).join(',')}${incomplete.length > 10 ? ',…' : ''}]` : ''),
  );
}

/**
 * Runs forever. The long-poll IS the pacing -- there is no sleep on the happy
 * path. The first call passes wait=0, or a freshly started bridge would sit
 * idle for a full wait before its first pass with orgs already waiting.
 *
 * A change that lands while a pass is running is missed by the listener (no
 * call is open to hear it). That costs latency, not correctness: the next call
 * returns the full list either way.
 */
async function reconcileLoop() {
  log(
    `reconcile: every org -> team + ${RECONCILE.apps.map(a => a.chart).join(', ')} on ${RECONCILE.host}` +
      ` (org id field: ${RECONCILE.orgIdField})`,
  );
  let first = true;
  let failures = 0;
  for (;;) {
    const started = Date.now();
    try {
      const orgs = await fetchOrgs(first ? 0 : RECONCILE.waitSeconds);
      first = false;
      await reconcileOnce(orgs);
      failures = 0;
    } catch (err) {
      failures++;
      log(`reconcile: pass failed (${failures} in a row) --`, err.message);
    }
    const backoff = failures ? Math.min(60000, 2000 * 2 ** Math.min(failures, 5)) : 0;
    const pause = Math.max(RECONCILE.minIntervalMs - (Date.now() - started), backoff, 0);
    if (pause) await new Promise(resolve => setTimeout(resolve, pause));
  }
}

// --- /provision, derive-the-id form ----------------------------------------

/**
 * `{ chart, name? }` instead of `{ websiteId, name, domain }`: the caller names
 * the app and the bridge works out the site id, so the hash lives in exactly
 * one place instead of being re-implemented in every app, in two languages,
 * where a drift would silently send events to a site that does not exist.
 *
 * The org is the one the GATEWAY stamped, never anything in the body, and the
 * host is this process's own config -- a caller that could name either could
 * name another org's bucket. Limited to the configured platform apps, so a
 * caller cannot create arbitrary sites in its org's team.
 */
async function handleProvisionForOrg(req, res, chart) {
  if (!RECONCILE.deriveReady) {
    deny(res, 503, 'Per-organisation analytics is not configured on this platform.');
    return;
  }
  const app = RECONCILE.apps.find(a => a.chart === chart);
  if (!app) {
    deny(res, 400, `chart must be one of: ${RECONCILE.apps.map(a => a.chart).join(', ')}.`);
    return;
  }
  const orgId = String(req.headers[ORG_HEADER] || '').toLowerCase();
  if (!UUID_RE.test(orgId)) {
    deny(res, 400, 'No organisation on this request, so there is no team to put the site in.');
    return;
  }

  const orgName = await orgNameFor(orgId);
  const teamId = await ensureTeam(orgId, orgName);
  const websiteId = siteIdFor(RECONCILE.host, chart, orgId);
  const outcome = await ensureSite(websiteId, siteNameFor(orgName, app.name), teamId);

  res.writeHead(outcome === 'created' ? 201 : 200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ websiteId, teamId, created: outcome === 'created' }));
}

// --- tenant sign-in ----------------------------------------------------------

/**
 * userId -> that tenant user's LOGIN token. Held here, never sent to a browser.
 *
 * Cached because /api/auth/login calls saveAuth with no expiry: every fresh
 * login leaves a Redis session that never goes away, so logging in on each
 * dashboard visit would pile them up. One login per tenant user per pod
 * lifetime, re-done only when Umami rejects the cached token.
 */
const tenantTokens = new Map();

/** Make sure the org's Umami user exists and has exactly the `view-only` role. */
async function ensureTenantUser(orgId) {
  const userId = tenantUserIdFor(orgId);
  const username = tenantUsernameFor(orgId);
  const password = derivePassword(TENANT_SIGNIN.secret, userId);

  // A missing user is a 200 with a literal null body, not a 404.
  const existing = await umamiGet(`/api/users/${userId}`);
  if (!existing?.id) {
    // view-only, not `user`: `user` can create websites and teams.
    await umamiSend('POST', '/api/users', { id: userId, username, password, role: 'view-only' });
    log('tenant: created user', username);
  } else if (existing.role !== 'view-only') {
    // Desired state, the way staff-setup reconciles its own account. A tenant
    // account with any wider role would be a cross-tenant leak the moment it
    // signed in -- `admin` short-circuits every permission check in Umami.
    await umamiSend('POST', `/api/users/${userId}`, { username, role: 'view-only' });
    tenantTokens.delete(userId);
    log('tenant: reset role of', username, 'from', existing.role, 'to view-only');
  }
  return { userId, username, password };
}

/** Make sure the user is a `team-view-only` member of the org's team. */
async function ensureMembership(teamId, userId) {
  const members = await umamiListAll(`/api/teams/${teamId}/users`);
  const mine = members.filter(m => (m.userId || m.user?.id) === userId);
  if (!mine.length) {
    // Checked first, never add-and-ignore: Umami does not reject a duplicate
    // add, it inserts a SECOND row.
    await umamiSend('POST', `/api/teams/${teamId}/users`, { userId, role: 'team-view-only' });
    log('tenant: added', userId, 'to team', teamId);
    return;
  }
  if (mine.some(m => m.role !== 'team-view-only')) {
    // team-view-only grants read and nothing else; any other team role lets
    // the tenant edit or delete their sites.
    await umamiSend('POST', `/api/teams/${teamId}/users/${userId}`, { role: 'team-view-only' });
    log('tenant: reset team role of', userId, 'to team-view-only');
  }
}

/**
 * Refuse unless the tenant user belongs to its own org's team and no other.
 *
 * Nothing here ever adds it anywhere else, so another membership means someone
 * did it by hand -- and signing in would then show that other org's sites.
 * Refused rather than repaired: removing memberships is not this code's call.
 */
async function assertOnlyTeam(userId, teamId) {
  const teams = await umamiListAll(`/api/users/${userId}/teams`);
  const others = teams.filter(t => t.id !== teamId);
  if (others.length) {
    log('tenant: REFUSED', userId, 'is also in team(s)', others.map(t => t.id).join(','));
    throw refuse('This analytics account is misconfigured. Ask a platform admin to check it.');
  }
}

function loginAs(username, password) {
  return fetch(`${UMAMI}${BASE_PATH}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
}

/** The tenant user's login token, from cache or a fresh login. */
async function tenantLoginToken(user, { fresh = false } = {}) {
  if (!fresh && tenantTokens.has(user.userId)) return tenantTokens.get(user.userId);

  let res = await loginAs(user.username, user.password);
  if (res.status === 401) {
    // The stored password no longer matches the derived one -- the secret was
    // rotated, or someone set it by hand. Put it back and log in again. This
    // signs out that user's other sessions, which is right after a rotation.
    await umamiSend('POST', `/api/users/${user.userId}`, { username: user.username, password: user.password });
    log('tenant: re-applied derived password for', user.username);
    res = await loginAs(user.username, user.password);
  }
  if (!res.ok) throw new Error(`tenant login failed: ${res.status}`);
  const body = await res.json();
  if (!body?.token) throw new Error('tenant login returned no token');
  tenantTokens.set(user.userId, body.token);
  return body.token;
}

/**
 * Mint the browser token for a tenant admin, and where to land them.
 *
 * /api/auth/sso mints only for the CALLER -- there is no "mint for user X" --
 * so the bridge logs in as the org's user first, then asks /sso for the
 * expiring token the browser receives.
 */
async function mintTenantBrowserToken(req) {
  const orgId = String(req.headers[ORG_HEADER] || '').toLowerCase();
  if (!UUID_RE.test(orgId)) throw refuse('No organisation on this sign-in, so there is no team to show.');

  const orgName = await orgNameFor(orgId);
  const teamId = await ensureTeam(orgId, orgName);
  const user = await ensureTenantUser(orgId);
  await ensureMembership(teamId, user.userId);
  await assertOnlyTeam(user.userId, teamId);

  const sso = token =>
    fetch(`${UMAMI}${BASE_PATH}/api/auth/sso`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
  let res = await sso(await tenantLoginToken(user));
  if (res.status === 401) res = await sso(await tenantLoginToken(user, { fresh: true }));
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`tenant sso mint failed: ${res.status} ${detail.slice(0, 160)}`);
  }
  const body = await res.json();
  if (!body?.token) throw new Error('tenant sso returned no token');

  // Last line of defence. /sso echoes the user it authenticated; an admin
  // would short-circuit every permission check in Umami and see every org.
  if (body.user?.isAdmin || body.user?.role === 'admin') {
    throw refuse('Refusing to sign a tenant in as an administrator.');
  }

  log('tenant: signed in org', orgId, 'as', user.username);
  // Straight into the team context. The personal /websites page lists only
  // sites the user OWNS -- none -- so landing there would show an empty page.
  return { token: body.token, landing: `/teams/${teamId}/websites` };
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

  // The query API. Same placement rationale as provisioning: after the denylist
  // so this can never become a way around it, and before the proxy so the path
  // is answered here rather than forwarded to Umami as if it were a page.
  //
  // No role check. The caller is an app, not a browser, carrying a platform key
  // the gateway has already validated -- there is no platform-admin in this
  // request to look for. Guarded at the dispatch point for the same reason as
  // above: an escaped rejection from this async callback would exit the process.
  const querySite = apiSiteId(pathname, QUERY_PATH);
  const schemaSite = querySite ? null : apiSiteId(pathname, SCHEMA_PATH);
  if (querySite || schemaSite) {
    try {
      if (querySite) await handleQuery(req, res, querySite);
      else await handleSchema(req, res, schemaSite);
    } catch (err) {
      log('query handler failed unexpectedly --', err.message);
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
    log('entry refused: none of', REQUIRED_ROLES.join(','), 'in', ROLE_HEADER);
    deny(res, 403, `This dashboard requires one of these roles: ${REQUIRED_ROLES.join(', ')}`);
    return;
  }

  // Which Umami account this person becomes. Staff wins when both are held --
  // it sees everything the tenant account can, so it never widens access.
  const roles = callerRoles(req);
  const asStaff = roles.includes(STAFF_ROLE);
  const asTenant = !asStaff && TENANT_SIGNIN.enabled && roles.includes(TENANT_ROLE);

  if (!asStaff && !asTenant) {
    // Admitted by the gateway, but not a role this bridge knows how to sign in
    // -- most likely tenant-admin while tenant sign-in is switched off. Refused
    // rather than falling back to the staff account, which would hand a
    // tenant admin every organisation's analytics.
    log('entry refused: role(s)', roles.join(',') || '(none)', 'map to no Umami account');
    deny(res, 403, 'Your role is not enabled for the analytics dashboard.');
    return;
  }

  try {
    const { token, landing } = asStaff
      ? { token: await mintBrowserToken(), landing: POST_SIGNIN_PATH }
      : await mintTenantBrowserToken(req);
    // Umami's /sso page validates `url` against open redirects itself
    // (isSafeRedirectUrl: must start with a single slash, no scheme).
    const target =
      `${BASE_PATH}/sso?token=${encodeURIComponent(token)}` +
      `&url=${encodeURIComponent(landing)}`;
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
    // A refusal we chose (no org, an account that is not what it should be)
    // is a 403; anything else is Umami or authz failing upstream.
    deny(res, err.status === 403 ? 403 : 502, err.status === 403 ? err.message : 'Could not sign in to analytics');
  }
});

server.listen(PORT, '0.0.0.0', () => {
  log(`listening on ${PORT}, proxying ${UMAMI}, base path "${BASE_PATH || '/'}"`);
  // After listen, so a slow or unreachable authz cannot delay readiness.
  registerRoutes();
  log(
    `tenant isolation: reconcile ${RECONCILE.enabled ? 'ON' : 'off'},` +
      ` derive-mode /provision ${RECONCILE.deriveReady ? 'ready' : 'not configured'},` +
      ` tenant sign-in ${TENANT_SIGNIN.enabled ? 'ON' : 'off'},` +
      ` entry roles ${REQUIRED_ROLES.join(',')}`,
  );
  log(
    QUERY_TABLES
      ? `query API: ON (schema "${QUERY_DB.schema}", read-only transactions, ` +
          `${QUERY_TIMEOUT_MS}ms statement timeout)`
      : 'query API: off -- no database configured; /query and /schema answer 503',
  );
  if (PROVISION_ADOPT_EXISTING) {
    log(
      'provision: ADOPTING existing sites -- turn BRIDGE_PROVISION_ADOPT_EXISTING off after the migration',
    );
  }
  // Never awaited, and it catches everything itself: a reconciler fault must
  // not take down the staff sign-in this same process serves.
  if (RECONCILE.enabled) reconcileLoop();
});
