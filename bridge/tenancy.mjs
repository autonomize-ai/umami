/**
 * Tenancy helpers for the login bridge — pure functions, no I/O.
 *
 * Kept out of server.mjs because server.mjs starts listening the moment it is
 * imported, which makes it untestable in isolation. Everything here that
 * decides an identifier is exercised by bridge/test/tenancy.test.mjs, and the
 * identifiers are the part of tenant isolation that fails SILENTLY when wrong:
 * a site id that drifts by one character is a site nothing ever writes to, and
 * Umami answers events for it with "Website not found" and drops them.
 */

import { createHash, createHmac } from 'node:crypto';

export const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Hash a seed into the 8-4-4-4-12 shape, with the version ('4') and variant
 * ('a') characters forced so Umami's strict uuid validation accepts it.
 *
 * BYTE-FOR-BYTE the same slicing as the genesis-fe chart's
 * `genesis-fe.umamiWebsiteId` helper:
 *
 *   printf "%s-%s-4%s-a%s-%s" (substr 0 8 $h) (substr 8 12 $h)
 *                             (substr 13 16 $h) (substr 17 20 $h) (substr 20 32 $h)
 *
 * Characters 12 and 16 of the digest are skipped on purpose — the helper does,
 * so this must. The test suite pins this against values rendered from that
 * helper; change one and the other has to change in the same commit.
 */
export function uuidFromSeed(seed) {
  const h = createHash('sha256').update(seed).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

/**
 * The analytics site id for one app, optionally scoped to one organisation.
 *
 * Without an org this reproduces the existing per-environment id exactly
 * (seed `${host}/${chart}`), which is how the old shared site stays
 * addressable — it becomes the staff-only archive and the destination for
 * logged-out traffic. With an org, the org id is one more path segment on the
 * same seed, so every tenant gets its own site from the same single deployment.
 *
 * `host` must be the SAME string genesis-lib.singleDomainHost produces
 * (global.routing.host). A different spelling of the same host — a trailing
 * slash, a scheme, a service DNS name — is a different hash and a different
 * site.
 */
export function siteIdFor(host, chart, orgId) {
  if (!host || !chart) throw new Error('siteIdFor needs a host and a chart name');
  return uuidFromSeed(orgId ? `${host}/${chart}/${orgId}` : `${host}/${chart}`);
}

/**
 * Team names carry the org id, because Umami's create-team API generates its
 * own id and takes no `id` — so a team can only ever be found again by name.
 *
 * But the name is also what Umami's team switcher DISPLAYS (TeamsButton renders
 * team.name), so a bare uuid would be every tenant admin's team label. The
 * compromise: a readable prefix, then the full org id, matched on the id alone.
 *
 * Budget: Umami caps team names at 50 (schema `VarChar(50)`, API `max(50)`).
 * 36 for the uuid + 3 for the separator leaves 11 for the org name.
 */
export const TEAM_NAME_MAX = 50;
export const TEAM_NAME_SEPARATOR = ' · ';
const ORG_ID_LEN = 36;
const PREFIX_MAX = TEAM_NAME_MAX - ORG_ID_LEN - TEAM_NAME_SEPARATOR.length;

export function teamNameFor(orgName, orgId) {
  if (!UUID_RE.test(orgId || '')) throw new Error(`teamNameFor: org id is not a uuid: ${orgId}`);
  const id = orgId.toLowerCase();
  const prefix = String(orgName || '').trim().replace(/\s+/g, ' ').slice(0, PREFIX_MAX).trim();
  return prefix ? `${prefix}${TEAM_NAME_SEPARATOR}${id}` : id;
}

/**
 * The org id a team belongs to, read from the LAST 36 characters of its name,
 * or null when the name does not end in one.
 *
 * Matching on the suffix, never the whole name, is what lets the readable
 * prefix change — an org renamed from "Acme" to "Acme Health" still owns the
 * same team, found by the same id.
 */
export function orgIdFromTeamName(name) {
  const tail = String(name || '').slice(-ORG_ID_LEN);
  return UUID_RE.test(tail) ? tail.toLowerCase() : null;
}

/**
 * The Umami user a tenant admin is signed in as — one per organisation.
 *
 * Deterministic, so the bridge never has to look the id up or store it: the
 * same org always maps to the same user. Namespaced so it can never collide
 * with a site id derived from the same org.
 */
export function tenantUserIdFor(orgId) {
  return uuidFromSeed(`umami-tenant-user/${String(orgId).toLowerCase()}`);
}

/** Lowercase on purpose: Umami lowercases usernames on create. */
export function tenantUsernameFor(orgId) {
  return `tenant-${String(orgId).toLowerCase()}`;
}

/**
 * The tenant user's password, derived rather than stored.
 *
 * WHY DERIVED, NOT RESET PER SIGN-IN: /api/auth/sso mints a token only for the
 * caller, so the bridge has to log in AS the tenant user — which needs its
 * password. Umami binds every token to the password hash (checkAuth rejects a
 * token whose `pwd` no longer matches), so resetting the password at each
 * sign-in would sign out every other session on that user. A value derived
 * from a secret and the user id is the same every time: nothing to store,
 * nothing invalidated.
 *
 * 43 characters of base64url — inside Umami's 8..255 password bounds.
 */
export function derivePassword(secret, userId) {
  if (!secret) throw new Error('derivePassword needs a secret');
  return createHmac('sha256', secret).update(`umami-tenant-user:${userId}`).digest('base64url');
}

/**
 * Parse BRIDGE_PLATFORM_APPS: a JSON array of { chart, name }.
 *
 * Strict, because a malformed entry is not a harmless typo — it is a site the
 * reconciler creates under a chart name no app will ever compute, so every
 * tenant gets an extra, permanently empty website.
 */
export function parsePlatformApps(raw) {
  if (!raw) return [];
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed)) throw new Error('BRIDGE_PLATFORM_APPS must be a JSON array');
  const seen = new Set();
  return parsed.map((entry, i) => {
    const chart = String(entry?.chart || '').trim();
    const name = String(entry?.name || '').trim();
    if (!/^[a-z0-9][a-z0-9-]*$/.test(chart)) {
      throw new Error(`BRIDGE_PLATFORM_APPS[${i}].chart must be a chart name, got ${JSON.stringify(entry?.chart)}`);
    }
    if (!name) throw new Error(`BRIDGE_PLATFORM_APPS[${i}].name is required`);
    if (seen.has(chart)) throw new Error(`BRIDGE_PLATFORM_APPS lists ${chart} twice`);
    seen.add(chart);
    return { chart, name };
  });
}

/** Comma-separated role list, trimmed, empties dropped. */
export function parseRoles(raw) {
  return String(raw || '')
    .split(',')
    .map(r => r.trim())
    .filter(Boolean);
}

/**
 * A website's display name. Umami caps website names at 100 characters, so a
 * long org name is truncated rather than letting the create call fail.
 */
export function siteNameFor(orgName, appName) {
  const name = orgName ? `${String(orgName).trim()} — ${appName}` : appName;
  return name.slice(0, 100);
}
