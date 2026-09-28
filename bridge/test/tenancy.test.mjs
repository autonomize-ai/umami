// Unit tests for the bridge's tenancy helpers.
//
//   node --test bridge/test/
//
// The site-id vectors below are not invented: they are the ids a live
// reconcile created on a genesis-local cluster for two sample orgs. If the
// hash ever drifts, every existing org site stops being addressable and events
// land nowhere -- silently. These tests are the tripwire.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  TEAM_NAME_MAX,
  UUID_RE,
  derivePassword,
  orgIdFromTeamName,
  parsePlatformApps,
  parseRoles,
  siteIdFor,
  siteNameFor,
  teamNameFor,
  tenantUserIdFor,
  tenantUsernameFor,
} from '../tenancy.mjs';

const ORG = '7f3a1c94-2b8e-4d51-9a06-c3e5d8f21b47';
const OTHER_ORG = '11111111-2222-4333-8444-555555555555';

test('siteIdFor reproduces the ids a live reconcile created', () => {
  const acme = 'f16d3ca9-dbf2-4e74-b878-d140e9a47629';
  const bravo = '9039805f-a885-4c16-a8f2-cd36082e208b';
  assert.equal(siteIdFor('genesis.localhost', 'genesis-fe', acme), '76037c8c-a0c3-40b0-a368-5fb64ee642a1');
  assert.equal(siteIdFor('genesis.localhost', 'genesis-tenant-mgmt', acme), '33ba5487-4856-4245-a686-9d5740d12b4b');
  assert.equal(siteIdFor('genesis.localhost', 'genesis-cc-fe', bravo), 'ae4e04a3-0c4c-4ec5-a00b-433a9acd52a8');
});

test('there is no site without an org', () => {
  // Every site belongs to one org's team; an org-less id would be a shared site.
  assert.throws(() => siteIdFor('genesis.dev.autonomize.ai', 'genesis-fe'), /org id/);
  assert.throws(() => siteIdFor('genesis.dev.autonomize.ai', 'genesis-fe', ''), /org id/);
});

test('per-org site ids are valid uuids, stable, and distinct per org and per app', () => {
  const a = siteIdFor('genesis.dev.autonomize.ai', 'genesis-fe', ORG);
  assert.match(a, UUID_RE);
  assert.equal(a, siteIdFor('genesis.dev.autonomize.ai', 'genesis-fe', ORG), 'same inputs, same id');
  assert.notEqual(a, siteIdFor('genesis.dev.autonomize.ai', 'genesis-fe', OTHER_ORG), 'org changes the id');
  assert.notEqual(a, siteIdFor('genesis.dev.autonomize.ai', 'genesis-cc-fe', ORG), 'app changes the id');
  // Version and variant characters are forced, for Umami's strict uuid check.
  assert.equal(a[14], '4');
  assert.equal(a[19], 'a');
});

test('host is taken literally — a different spelling is a different site', () => {
  const plain = siteIdFor('genesis.dev.autonomize.ai', 'genesis-fe', ORG);
  assert.notEqual(plain, siteIdFor('genesis.dev.autonomize.ai/', 'genesis-fe', ORG));
  assert.notEqual(plain, siteIdFor('https://genesis.dev.autonomize.ai', 'genesis-fe', ORG));
});

test('siteIdFor refuses to hash without a host or chart', () => {
  assert.throws(() => siteIdFor('', 'genesis-fe', ORG));
  assert.throws(() => siteIdFor('genesis.localhost', '', ORG));
});

test('team names fit Umami’s 50-char limit and keep the org id recoverable', () => {
  const long = teamNameFor('Acme Health Partners of the Midwest', ORG);
  assert.ok(long.length <= TEAM_NAME_MAX, `${long.length} chars`);
  assert.ok(long.endsWith(ORG));
  assert.equal(orgIdFromTeamName(long), ORG);

  const short = teamNameFor('Acme', ORG);
  assert.equal(short, `Acme · ${ORG}`);
  assert.equal(orgIdFromTeamName(short), ORG);
});

test('an org with no name gets the bare id as its team name', () => {
  assert.equal(teamNameFor('', ORG), ORG);
  assert.equal(teamNameFor('   ', ORG), ORG);
  assert.equal(orgIdFromTeamName(ORG), ORG);
});

test('org ids are normalised to lowercase in team names', () => {
  assert.equal(orgIdFromTeamName(teamNameFor('Acme', ORG.toUpperCase())), ORG);
});

test('a renamed org still maps to the same team', () => {
  assert.equal(orgIdFromTeamName(teamNameFor('Acme', ORG)), orgIdFromTeamName(teamNameFor('Acme Health', ORG)));
});

test('names not ending in an org id are not claimed', () => {
  assert.equal(orgIdFromTeamName('Some Other Team'), null);
  assert.equal(orgIdFromTeamName(''), null);
  assert.equal(orgIdFromTeamName(null), null);
});

test('teamNameFor rejects a non-uuid org id', () => {
  assert.throws(() => teamNameFor('Acme', 'not-a-uuid'));
});

test('tenant user identity is deterministic, valid, and distinct from site ids', () => {
  const id = tenantUserIdFor(ORG);
  assert.match(id, UUID_RE);
  assert.equal(id, tenantUserIdFor(ORG.toUpperCase()));
  assert.notEqual(id, tenantUserIdFor(OTHER_ORG));
  assert.notEqual(id, siteIdFor('genesis.dev.autonomize.ai', 'genesis-fe', ORG));
  assert.equal(tenantUsernameFor(ORG.toUpperCase()), `tenant-${ORG}`);
});

test('derived passwords are stable, secret-dependent, and within Umami’s bounds', () => {
  const userId = tenantUserIdFor(ORG);
  const p = derivePassword('s3cret', userId);
  assert.equal(p, derivePassword('s3cret', userId));
  assert.notEqual(p, derivePassword('other', userId));
  assert.notEqual(p, derivePassword('s3cret', tenantUserIdFor(OTHER_ORG)));
  assert.ok(p.length >= 8 && p.length <= 255);
  assert.throws(() => derivePassword('', userId));
});

test('parsePlatformApps accepts the chart list and rejects malformed entries', () => {
  const apps = parsePlatformApps(
    '[{"chart":"genesis-fe","name":"AI Studio"},{"chart":"genesis-tenant-mgmt","name":"Admin Console"}]',
  );
  assert.deepEqual(apps.map(a => a.chart), ['genesis-fe', 'genesis-tenant-mgmt']);
  assert.deepEqual(parsePlatformApps(''), []);
  assert.throws(() => parsePlatformApps('{"chart":"x"}'), /array/);
  assert.throws(() => parsePlatformApps('[{"chart":"Genesis FE","name":"x"}]'), /chart name/);
  assert.throws(() => parsePlatformApps('[{"chart":"genesis-fe"}]'), /name is required/);
  assert.throws(
    () => parsePlatformApps('[{"chart":"genesis-fe","name":"a"},{"chart":"genesis-fe","name":"b"}]'),
    /twice/,
  );
});

test('parseRoles splits and trims', () => {
  assert.deepEqual(parseRoles('platform-admin, tenant-admin ,'), ['platform-admin', 'tenant-admin']);
  assert.deepEqual(parseRoles(''), []);
});

test('site names stay within Umami’s 100-char limit', () => {
  assert.equal(siteNameFor('Acme', 'AI Studio'), 'Acme — AI Studio');
  assert.equal(siteNameFor('', 'AI Studio'), 'AI Studio');
  assert.ok(siteNameFor('x'.repeat(200), 'AI Studio').length <= 100);
});
