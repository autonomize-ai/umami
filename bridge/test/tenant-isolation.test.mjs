// Integration test for the bridge's tenant isolation: the REAL server.mjs,
// run as a child process against an in-memory fake of the Umami and
// genesis-authz endpoints it calls.
//
//   node --test bridge/test/
//
// The fake mirrors the behaviours the bridge depends on, each checked against
// Umami's source before it was written down here:
//
//   * POST /api/teams answers with createTeam's transaction result -- an ARRAY
//     [team, ownerMembership] -- and makes the caller team-owner
//     (src/app/api/teams/route.ts, src/queries/prisma/team.ts createTeam)
//   * POST /api/websites sets userId only when no teamId is given
//     (src/app/api/websites/route.ts)
//   * GET /api/websites/:id and GET /api/users/:id answer 200 + null when absent
//   * listings are paged: { data, count, page, pageSize }
//   * /api/auth/sso mints only for the caller (src/app/api/auth/sso/route.ts)
//
// What this cannot prove is that real Umami still behaves this way after an
// upgrade -- that is what bridge/test/dashboard-flow.mjs, against a live
// cluster, is for.

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import http from 'node:http';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { siteIdFor, teamNameFor, tenantUserIdFor } from '../tenancy.mjs';

const HOST = 'genesis.test.example';
const ORG_A = '7f3a1c94-2b8e-4d51-9a06-c3e5d8f21b47';
const ORG_B = '11111111-2222-4333-8444-555555555555';
const ORG_C = '99999999-8888-4777-a666-555555555555';
const STAFF = { id: '00000000-0000-4000-a000-000000000001', username: 'staff', password: 'staff-pw', role: 'admin' };
const APPS = [
  { chart: 'genesis-fe', name: 'AI Studio' },
  { chart: 'genesis-cc-fe', name: 'Command Center' },
  { chart: 'genesis-tenant-mgmt', name: 'Admin Console' },
];

// --- the fake --------------------------------------------------------------

const state = {
  orgs: [
    { id: 'int-a', keycloak_id: ORG_A, name: 'Acme' },
    { id: 'int-b', keycloak_id: ORG_B, name: 'Bravo' },
  ],
  users: new Map([[STAFF.id, { ...STAFF }]]),
  teams: new Map(),
  members: [],
  websites: new Map(),
  teamCreates: [],
  seq: 0,
};

const uid = () => `aaaaaaaa-0000-4000-a000-${String(++state.seq).padStart(12, '0')}`;

function paged(rows, url) {
  const page = Number(url.searchParams.get('page') || 1);
  const size = Number(url.searchParams.get('pageSize') || 10);
  return { data: rows.slice((page - 1) * size, page * size), count: rows.length, page, pageSize: size };
}

function bearerUser(req) {
  const token = String(req.headers.authorization || '').replace(/^Bearer /, '');
  if (token === 'staff-login') return state.users.get(STAFF.id);
  const m = token.match(/^login-(.+)$/);
  return m ? state.users.get(m[1]) : null;
}

async function body(req) {
  let raw = '';
  for await (const chunk of req) raw += chunk;
  return raw ? JSON.parse(raw) : {};
}

function send(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

const fake = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://fake');
  const p = url.pathname;
  // Matches against the path BELOW /umami/api -- the routes are written that way.
  const m = re => p.slice('/umami/api'.length).match(re);

  // genesis-authz
  if (p === '/internal/authz/routes/register') return send(res, 200, {});
  if (p === '/internal/authz/platform/organizations') {
    if (req.headers['x-internal-call'] !== 'authz-key') return send(res, 401, {});
    return send(res, 200, state.orgs);
  }

  if (!p.startsWith('/umami/api/')) return send(res, 404, {});
  const api = p.slice('/umami/api'.length);

  if (req.method === 'POST' && api === '/auth/login') {
    const { username, password } = await body(req);
    const user = [...state.users.values()].find(u => u.username === username);
    if (!user || user.password !== password) return send(res, 401, { code: 'incorrect-username-password' });
    return send(res, 200, { token: user.id === STAFF.id ? 'staff-login' : `login-${user.id}` });
  }

  const caller = bearerUser(req);
  if (!caller) return send(res, 401, {});
  const isAdmin = caller.role === 'admin';

  if (req.method === 'POST' && api === '/auth/sso') {
    return send(res, 200, { user: { id: caller.id, role: caller.role, isAdmin }, token: `sso-${caller.id}` });
  }

  // Everything below is admin API the bridge calls as staff.
  if (!isAdmin) return send(res, 401, {});

  if (req.method === 'GET' && api === '/admin/teams') return send(res, 200, paged([...state.teams.values()], url));
  if (req.method === 'GET' && api === '/admin/websites') return send(res, 200, paged([...state.websites.values()], url));

  if (req.method === 'POST' && api === '/teams') {
    const { name } = await body(req);
    // Widen the race window so a missing lock would show up as two teams.
    await new Promise(r => setTimeout(r, 30));
    const team = { id: uid(), name, createdAt: new Date(Date.now() + state.seq).toISOString(), deletedAt: null };
    state.teams.set(team.id, team);
    state.teamCreates.push(name);
    const owner = { id: uid(), teamId: team.id, userId: caller.id, role: 'team-owner' };
    state.members.push(owner);
    return send(res, 200, [team, owner]);
  }
  let hit = m(/^\/teams\/([^/]+)$/);
  if (req.method === 'POST' && hit) {
    const { name } = await body(req);
    state.teams.get(hit[1]).name = name;
    return send(res, 200, state.teams.get(hit[1]));
  }
  hit = m(/^\/teams\/([^/]+)\/users$/);
  if (hit && req.method === 'GET') return send(res, 200, paged(state.members.filter(x => x.teamId === hit[1]), url));
  if (hit && req.method === 'POST') {
    const { userId, role } = await body(req);
    state.members.push({ id: uid(), teamId: hit[1], userId, role });
    return send(res, 200, {});
  }
  hit = m(/^\/teams\/([^/]+)\/users\/([^/]+)$/);
  if (hit && req.method === 'POST') {
    const { role } = await body(req);
    for (const x of state.members) if (x.teamId === hit[1] && x.userId === hit[2]) x.role = role;
    return send(res, 200, {});
  }

  hit = m(/^\/websites\/([^/]+)$/);
  if (hit && req.method === 'GET') return send(res, 200, state.websites.get(hit[1]) || null);
  if (req.method === 'POST' && api === '/websites') {
    const { id, name, domain, teamId } = await body(req);
    const site = { id, name, domain, teamId: teamId || null, userId: teamId ? null : caller.id };
    state.websites.set(id, site);
    return send(res, 200, site);
  }
  hit = m(/^\/websites\/([^/]+)\/transfer$/);
  if (hit && req.method === 'POST') {
    const { teamId } = await body(req);
    Object.assign(state.websites.get(hit[1]), { teamId, userId: null });
    return send(res, 200, {});
  }

  hit = m(/^\/users\/([^/]+)$/);
  if (hit && req.method === 'GET') {
    const u = state.users.get(hit[1]);
    return send(res, 200, u ? { id: u.id, username: u.username, role: u.role } : null);
  }
  if (hit && req.method === 'POST') {
    Object.assign(state.users.get(hit[1]), await body(req));
    return send(res, 200, {});
  }
  if (req.method === 'POST' && api === '/users') {
    const { id, username, password, role } = await body(req);
    state.users.set(id, { id, username: username.toLowerCase(), password, role });
    return send(res, 200, {});
  }
  hit = m(/^\/users\/([^/]+)\/teams$/);
  if (hit && req.method === 'GET') {
    const ids = new Set(state.members.filter(x => x.userId === hit[1]).map(x => x.teamId));
    return send(res, 200, paged([...state.teams.values()].filter(t => ids.has(t.id)), url));
  }

  return send(res, 404, { error: `fake has no ${req.method} ${api}` });
});

// --- bridge processes ------------------------------------------------------

const BRIDGE = fileURLToPath(new URL('../server.mjs', import.meta.url));
const children = [];
let fakeUrl;
let bridgeUrl;
let bridgeNoTenantUrl;
let bridgeLog = '';

function freePort() {
  return new Promise(resolve => {
    const s = http.createServer().listen(0, () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

async function startBridge(extraEnv) {
  const port = await freePort();
  const child = spawn(process.execPath, [BRIDGE], {
    env: {
      PATH: process.env.PATH,
      BRIDGE_PORT: String(port),
      UMAMI_INTERNAL_URL: fakeUrl,
      BASE_PATH: '/umami',
      UMAMI_STAFF_USER: STAFF.username,
      UMAMI_STAFF_PASSWORD: STAFF.password,
      AUTHZ_INTERNAL_URL: fakeUrl,
      AUTHZ_INTERNAL_KEY: 'authz-key',
      BRIDGE_REQUIRED_ROLES: 'platform-admin,tenant-admin',
      BRIDGE_PLATFORM_HOST: HOST,
      BRIDGE_PLATFORM_APPS: JSON.stringify(APPS),
      BRIDGE_RECONCILE_POLL_SECONDS: '2',
      BRIDGE_RECONCILE_REQUEST_TIMEOUT_SECONDS: '5',
      BRIDGE_RECONCILE_MIN_INTERVAL_SECONDS: '1',
      ...extraEnv,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  children.push(child);
  child.stdout.on('data', d => (bridgeLog += d));
  child.stderr.on('data', d => (bridgeLog += d));
  const url = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(`${url}/bridge-healthz`)).ok) return url;
    } catch {}
    await new Promise(r => setTimeout(r, 50));
  }
  throw new Error(`bridge did not start:\n${bridgeLog}`);
}

async function waitFor(check, what, ms = 8000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (check()) return;
    await new Promise(r => setTimeout(r, 50));
  }
  throw new Error(`timed out waiting for ${what}\n--- bridge log ---\n${bridgeLog}`);
}

const teamOf = orgId => [...state.teams.values()].find(t => t.name.endsWith(orgId));
const entry = (url, headers) => fetch(`${url}/umami`, { redirect: 'manual', headers });

before(async () => {
  await new Promise(r => fake.listen(0, '127.0.0.1', r));
  fakeUrl = `http://127.0.0.1:${fake.address().port}`;
  bridgeUrl = await startBridge({ BRIDGE_RECONCILE_ENABLED: 'true', BRIDGE_TENANT_SIGNIN_ENABLED: 'true', BRIDGE_TENANT_PASSWORD_SECRET: 's3cret' });
  bridgeNoTenantUrl = await startBridge({ BRIDGE_RECONCILE_ENABLED: 'false', BRIDGE_TENANT_SIGNIN_ENABLED: 'false' });
});

after(() => {
  for (const c of children) c.kill();
  fake.close();
});

// --- tests -----------------------------------------------------------------

test('the reconciler gives every org one team holding one team-owned site per platform app', async () => {
  await waitFor(() => state.websites.size >= 2 * APPS.length + APPS.length, 'reconcile to create all sites');

  for (const [orgId, name] of [[ORG_A, 'Acme'], [ORG_B, 'Bravo']]) {
    const team = teamOf(orgId);
    assert.ok(team, `team for ${name}`);
    assert.equal(team.name, teamNameFor(name, orgId));
    for (const app of APPS) {
      const site = state.websites.get(siteIdFor(HOST, app.chart, orgId));
      assert.ok(site, `${name} site for ${app.chart}`);
      assert.equal(site.teamId, team.id, 'site is in the org’s team');
      assert.equal(site.userId, null, 'site is team-owned, so canViewWebsite reaches the team branch');
    }
  }
  assert.equal(state.teamCreates.length, 2, 'exactly one team per org');
  assert.match(bridgeLog, /reconcile_once done: orgs=2/);
});

test('the reconciler keeps an unscoped, staff-owned site per app for logged-out traffic', async () => {
  for (const app of APPS) {
    const site = state.websites.get(siteIdFor(HOST, app.chart));
    assert.ok(site, `unscoped ${app.chart}`);
    assert.equal(site.teamId, null);
    assert.equal(site.userId, STAFF.id);
  }
});

test('a later pass changes nothing on a healthy system', async () => {
  const sites = state.websites.size;
  const teams = state.teams.size;
  const passes = (bridgeLog.match(/reconcile_once done/g) || []).length;
  await waitFor(() => (bridgeLog.match(/reconcile_once done/g) || []).length > passes + 1, 'two more passes');
  assert.equal(state.websites.size, sites);
  assert.equal(state.teams.size, teams);
});

test('/provision derive form returns the org’s site id, from the gateway-stamped org', async () => {
  const res = await fetch(`${bridgeUrl}/umami/provision`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-organization-id': ORG_A },
    body: JSON.stringify({ chart: 'genesis-fe' }),
  });
  assert.equal(res.status, 200);
  const out = await res.json();
  assert.equal(out.websiteId, siteIdFor(HOST, 'genesis-fe', ORG_A));
  assert.equal(out.teamId, teamOf(ORG_A).id);
});

test('/provision derive form refuses an unknown chart and a request with no org', async () => {
  const unknown = await fetch(`${bridgeUrl}/umami/provision`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-organization-id': ORG_A },
    body: JSON.stringify({ chart: 'something-else' }),
  });
  assert.equal(unknown.status, 400);
  const noOrg = await fetch(`${bridgeUrl}/umami/provision`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ chart: 'genesis-fe' }),
  });
  assert.equal(noOrg.status, 400);
});

test('concurrent first calls for a brand-new org create exactly one team', async () => {
  const before = state.teamCreates.length;
  const calls = Array.from({ length: 6 }, () =>
    fetch(`${bridgeUrl}/umami/provision`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-organization-id': ORG_C },
      body: JSON.stringify({ chart: 'genesis-fe' }),
    }),
  );
  const results = await Promise.all(calls);
  for (const r of results) assert.ok(r.status === 200 || r.status === 201, `status ${r.status}`);
  const ids = new Set(await Promise.all(results.map(async r => (await r.json()).teamId)));
  assert.equal(ids.size, 1, 'every caller got the same team');
  assert.equal(state.teamCreates.length - before, 1, 'one team created, not six');
});

test('a platform admin is signed in as the staff account and lands on /websites', async () => {
  const res = await entry(bridgeUrl, { 'x-user-roles': 'platform-admin' });
  assert.equal(res.status, 302);
  const loc = new URL(res.headers.get('location'), 'http://x');
  assert.equal(loc.pathname, '/umami/sso');
  assert.equal(loc.searchParams.get('token'), `sso-${STAFF.id}`);
  assert.equal(loc.searchParams.get('url'), '/websites');
});

test('a tenant admin is signed in as their org’s view-only user and lands in their team', async () => {
  const res = await entry(bridgeUrl, { 'x-user-roles': 'tenant-admin', 'x-organization-id': ORG_A });
  assert.equal(res.status, 302, bridgeLog);
  const loc = new URL(res.headers.get('location'), 'http://x');
  const userId = tenantUserIdFor(ORG_A);
  assert.equal(loc.searchParams.get('token'), `sso-${userId}`);
  assert.equal(loc.searchParams.get('url'), `/teams/${teamOf(ORG_A).id}/websites`);

  const user = state.users.get(userId);
  assert.equal(user.role, 'view-only');
  const memberships = state.members.filter(x => x.userId === userId);
  assert.deepEqual(memberships.map(x => [x.teamId, x.role]), [[teamOf(ORG_A).id, 'team-view-only']]);
});

test('signing the same tenant in again adds no duplicate membership', async () => {
  await entry(bridgeUrl, { 'x-user-roles': 'tenant-admin', 'x-organization-id': ORG_A });
  assert.equal(state.members.filter(x => x.userId === tenantUserIdFor(ORG_A)).length, 1);
});

test('a tenant account elevated by hand is put back to view-only before signing in', async () => {
  const userId = tenantUserIdFor(ORG_A);
  state.users.get(userId).role = 'admin';
  const res = await entry(bridgeUrl, { 'x-user-roles': 'tenant-admin', 'x-organization-id': ORG_A });
  assert.equal(res.status, 302, bridgeLog);
  assert.equal(state.users.get(userId).role, 'view-only');
});

test('a tenant account that is also in another org’s team is refused', async () => {
  const userId = tenantUserIdFor(ORG_B);
  await entry(bridgeUrl, { 'x-user-roles': 'tenant-admin', 'x-organization-id': ORG_B });
  state.members.push({ id: uid(), teamId: teamOf(ORG_A).id, userId, role: 'team-view-only' });
  const res = await entry(bridgeUrl, { 'x-user-roles': 'tenant-admin', 'x-organization-id': ORG_B });
  assert.equal(res.status, 403);
  assert.match((await res.json()).error, /misconfigured/, 'refused for the membership, not something else');
});

test('a tenant admin with no organisation is refused', async () => {
  const res = await entry(bridgeUrl, { 'x-user-roles': 'tenant-admin' });
  assert.equal(res.status, 403);
  assert.match((await res.json()).error, /No organisation/);
});

test('holding both roles signs you in as staff', async () => {
  const res = await entry(bridgeUrl, { 'x-user-roles': 'tenant-admin,platform-admin', 'x-organization-id': ORG_A });
  assert.equal(new URL(res.headers.get('location'), 'http://x').searchParams.get('token'), `sso-${STAFF.id}`);
});

test('with tenant sign-in off, a tenant admin is refused and never falls back to staff', async () => {
  const res = await entry(bridgeNoTenantUrl, { 'x-user-roles': 'tenant-admin', 'x-organization-id': ORG_A });
  assert.equal(res.status, 403);
  assert.match((await res.json()).error, /not enabled/);
  const staff = await entry(bridgeNoTenantUrl, { 'x-user-roles': 'platform-admin' });
  assert.equal(staff.status, 302, 'staff sign-in unaffected');
});

test('a caller with neither role is refused', async () => {
  const res = await entry(bridgeUrl, { 'x-user-roles': 'developer' });
  assert.equal(res.status, 403);
});

test('the original /provision form still works unchanged', async () => {
  const websiteId = '12345678-1234-4234-a234-123456789abc';
  const res = await fetch(`${bridgeUrl}/umami/provision`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-organization-id': ORG_A },
    body: JSON.stringify({ websiteId, name: 'Marketplace app', domain: 'app.example.com' }),
  });
  assert.equal(res.status, 201);
  assert.equal(state.websites.get(websiteId).userId, STAFF.id);
});
