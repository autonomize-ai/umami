// Unit tests for the query API's request grammar and SQL builders.
//
//   node --test bridge/test/
//
// These cover what can be checked without a database: that every refusal is a
// named 400/422, that caller text only ever reaches SQL as a bind parameter,
// and that every statement is pinned to the site from the path.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  buildAggregateSql,
  buildEventsSql,
  buildNestedEventsSql,
  buildPropsSql,
  buildSchemaSql,
  buildSessionsPageSql,
  decodeProp,
  parseQueryRequest,
  parseWindow,
  QueryError,
  shapeAggregate,
  tablesFor,
} from '../query.mjs';

const SITE = '6f1c2a1e-3b0d-4c7e-9a51-2f8d0b4e7c19';
const LIMITS = { maxEventsPage: 1000, maxSessionsPage: 200, maxAggregateRows: 10000 };
const T = tablesFor('umami');
const WINDOW = { from: '2026-09-01T00:00:00Z', to: '2026-10-01T00:00:00Z' };

const parse = body => parseQueryRequest(body, LIMITS);
const refuses = (body, status, pattern) =>
  assert.throws(
    () => parse(body),
    err => err instanceof QueryError && err.status === status && pattern.test(err.message),
  );

test('the documented events request parses', () => {
  const spec = parse({
    mode: 'events',
    window: WINDOW,
    where: {
      event_type: 'custom',
      event_names: ['record.exported'],
      event_props: [{ key: 'format', op: 'eq', value: 'csv' }],
    },
    select: {
      event_fields: ['id', 'session_id', 'created_at', 'type', 'name', 'url_path'],
      event_props: ['format', 'rows'],
    },
    page: { number: 1, size: 1000 },
  });
  assert.equal(spec.where.eventType, 2);
  assert.deepEqual(spec.eventProps, { keys: ['format', 'rows'] });
  assert.deepEqual(spec.page, { number: 1, size: 1000 });
});

test('the window is required, ordered and parseable, with no cap on width', () => {
  refuses({ mode: 'events' }, 422, /window/);
  refuses({ mode: 'events', window: { from: WINDOW.from } }, 422, /window\.to is required/);
  refuses({ mode: 'events', window: { from: 'yesterday', to: WINDOW.to } }, 422, /window\.from/);
  refuses({ mode: 'events', window: { from: WINDOW.to, to: WINDOW.from } }, 422, /earlier/);
  // Ten years is answered: the cost bound is the statement timeout, not the window.
  const w = parseWindow('2016-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
  assert.equal(w.to.getUTCFullYear(), 2026);
  // Epoch milliseconds, as a number or a numeric string.
  assert.equal(parseWindow(0, '1000').to.getTime(), 1000);
  // Finite, but past what a Date holds: a 422 here, not an invalid timestamp
  // for Postgres to reject as a 502.
  refuses({ mode: 'events', window: { from: 1e17, to: 2e17 } }, 422, /window\.from/);
  refuses({ mode: 'events', window: { from: 0, to: '9e15' } }, 422, /window\.to/);
});

test('a part the mode does not use is refused, not ignored', () => {
  refuses(
    { mode: 'aggregate', window: WINDOW, measures: [{ as: 'n', fn: 'count' }], page: {} },
    400,
    /"page" is not used/,
  );
  refuses({ mode: 'events', window: WINDOW, group_by: [] }, 400, /"group_by" is not used/);
  refuses({ mode: 'events', window: WINDOW, timezone: 'UTC' }, 400, /"timezone" is not used/);
  refuses({ mode: 'sql', window: WINDOW }, 400, /mode must be one of/);
});

test('fields that carry identifying text are not reachable', () => {
  for (const field of [
    'page_title',
    'url_query',
    'referrer_query',
    'referrer_path',
    'distinct_id',
    'gclid',
  ]) {
    refuses(
      { mode: 'events', window: WINDOW, select: { event_fields: [field] } },
      400,
      /Unknown field/,
    );
    refuses({ mode: 'events', window: WINDOW, where: { [field]: 'x' } }, 400, /Unknown field/);
    refuses(
      {
        mode: 'aggregate',
        window: WINDOW,
        group_by: [field],
        measures: [{ as: 'n', fn: 'count' }],
      },
      400,
      /not groupable/,
    );
  }
  refuses(
    { mode: 'events', window: WINDOW, where: { session: { distinct_id: 'x' } } },
    400,
    /Unknown field/,
  );
});

test('property filters validate their operator and value shape', () => {
  const w = f => ({ mode: 'events', window: WINDOW, where: { event_props: [f] } });
  refuses(w({ key: 'k', op: 'like', value: 'x' }), 400, /op must be one of/);
  refuses(w({ key: 'k', op: 'exists', value: 'x' }), 400, /not used with op "exists"/);
  refuses(w({ key: 'k', op: 'in', value: [] }), 400, /non-empty list/);
  refuses(w({ key: 'k', op: 'in', value: ['a', 1] }), 400, /one type/);
  refuses(
    w({ key: 'k', op: 'eq', value: { nested: true } }),
    400,
    /string, a finite number or a boolean/,
  );
  refuses(w({ key: '', op: 'eq', value: 'x' }), 400, /key must be a non-empty string/);
  refuses(w({ key: 'k', op: 'eq', value: 'x', extra: 1 }), 400, /Unknown field "extra"/);
});

test('page size is bounded per mode', () => {
  refuses({ mode: 'events', window: WINDOW, page: { size: 1001 } }, 400, /page\.size/);
  refuses({ mode: 'sessions', window: WINDOW, page: { size: 201 } }, 400, /page\.size/);
  refuses({ mode: 'events', window: WINDOW, page: { number: 0 } }, 400, /page\.number/);
  assert.deepEqual(parse({ mode: 'events', window: WINDOW }).page, { number: 1, size: 100 });
});

test('event fields in a sessions select need include_events', () => {
  refuses(
    { mode: 'sessions', window: WINDOW, select: { event_fields: ['id'] } },
    400,
    /include_events/,
  );
  const spec = parse({
    mode: 'sessions',
    window: WINDOW,
    select: { include_events: true, event_fields: ['id'] },
  });
  assert.equal(spec.includeEvents, true);
});

test('caller text reaches SQL only as bind parameters', () => {
  const evil = "x'); DROP TABLE website_event; --";
  const spec = parse({
    mode: 'events',
    window: WINDOW,
    where: {
      event_names: [evil],
      hostname: evil,
      url_path: { op: 'starts_with', value: evil },
      session: { country: evil },
      event_props: [{ key: evil, op: 'eq', value: evil }],
      session_props: [{ key: evil, op: 'not_in', value: [evil] }],
    },
  });
  const { text, values } = buildEventsSql(spec, SITE, T);
  assert.ok(!text.includes('DROP'), text);
  assert.ok(values.some(v => v === evil));
  // Every placeholder the text uses has a value, and every value is used.
  const used = new Set([...text.matchAll(/\$(\d+)/g)].map(m => Number(m[1])));
  assert.equal(used.size, values.length);
  assert.equal(Math.max(...used), values.length);
});

test('every statement is pinned to the site, including property subqueries', () => {
  const spec = parse({
    mode: 'events',
    window: WINDOW,
    where: { event_props: [{ key: 'format', op: 'neq', value: 'csv' }] },
  });
  const { text, values } = buildEventsSql(spec, SITE, T);
  assert.match(text, /e\.website_id = \$1::uuid/);
  assert.equal(values[0], SITE);
  assert.match(
    text,
    /NOT EXISTS \(SELECT 1 FROM "umami"\."event_data" pf WHERE pf\.website_id = e\.website_id/,
  );
  for (const q of [
    buildPropsSql('event', SITE, [SITE], { all: true }, T),
    buildPropsSql('session', SITE, [SITE], { keys: ['plan'] }, T),
  ]) {
    assert.match(q.text, /website_id = \$1::uuid/);
    assert.equal(q.values[0], SITE);
  }
  const schema = buildSchemaSql(SITE, parseWindow(WINDOW.from, WINDOW.to), 1000, T);
  for (const q of Object.values(schema)) {
    assert.match(q.text, /website_id = \$1::uuid/);
    assert.equal(q.values[0], SITE);
  }
});

test('starts_with escapes LIKE wildcards', () => {
  const spec = parse({
    mode: 'events',
    window: WINDOW,
    where: { url_path: { op: 'starts_with', value: '/a_b%c' } },
  });
  const { values } = buildEventsSql(spec, SITE, T);
  assert.ok(values.includes('/a\\_b\\%c%'));
});

test('pages fetch one extra row so has_more needs no count', () => {
  const spec = parse({ mode: 'events', window: WINDOW, page: { number: 3, size: 50 } });
  const { values } = buildEventsSql(spec, SITE, T);
  assert.deepEqual(values.slice(-2), [51, 100]);
  const s = parse({ mode: 'sessions', window: WINDOW, page: { number: 2, size: 10 } });
  assert.deepEqual(buildSessionsPageSql(s, SITE, T).values.slice(-2), [11, 10]);
  const n = buildNestedEventsSql(s, SITE, [SITE], 100, T);
  assert.equal(n.values.at(-1), 101);
});

test('the documented aggregate request builds one grouped statement', () => {
  const spec = parse({
    mode: 'aggregate',
    window: WINDOW,
    timezone: 'America/New_York',
    where: { event_type: 'custom' },
    group_by: ['bucket:day', 'event_name'],
    measures: [
      { as: 'events', fn: 'count' },
      { as: 'sessions', fn: 'count_distinct', of: 'session_id' },
    ],
    limit: 1000,
  });
  const { text, values } = buildAggregateSql(spec, SITE, T);
  assert.match(text, /date_trunc\('day', \(e\.created_at AT TIME ZONE \$1\)\)/);
  assert.match(text, /GROUP BY 1, 2 ORDER BY 1, 2 LIMIT \$\d+$/);
  assert.equal(values[0], 'America/New_York');
  assert.equal(values.at(-1), 1001);
});

test('aggregate property groupings and measures share one join per key', () => {
  const spec = parse({
    mode: 'aggregate',
    window: WINDOW,
    group_by: ['event_prop:format', 'session:country'],
    measures: [
      { as: 'rows', fn: 'sum', of: 'event_prop:rows' },
      { as: 'formats', fn: 'count_distinct', of: 'event_prop:format' },
      {
        as: 'csv',
        fn: 'count',
        where: { event_props: [{ key: 'format', op: 'eq', value: 'csv' }] },
      },
    ],
  });
  const { text } = buildAggregateSql(spec, SITE, T);
  assert.equal((text.match(/LEFT JOIN "umami"\."event_data"/g) || []).length, 2);
  assert.match(text, / JOIN "umami"\."session" s ON/);
  assert.match(text, /COUNT\(\*\) FILTER \(WHERE EXISTS/);
});

test('aggregate refuses what it cannot compute', () => {
  const agg = extra => ({ mode: 'aggregate', window: WINDOW, ...extra });
  refuses(agg({}), 400, /measures must be/);
  refuses(agg({ measures: [{ as: 'n', fn: 'median' }] }), 400, /fn must be one of/);
  refuses(agg({ measures: [{ as: 'n', fn: 'sum', of: 'session_id' }] }), 400, /numeric property/);
  refuses(agg({ measures: [{ as: 'n', fn: 'min', of: 'url_path' }] }), 400, /created_at/);
  refuses(agg({ measures: [{ as: 'Bad Name', fn: 'count' }] }), 400, /\.as must be/);
  refuses(
    agg({ group_by: ['event_name'], measures: [{ as: 'event_name', fn: 'count' }] }),
    400,
    /already used/,
  );
  refuses(
    agg({ group_by: ['bucket:minute'], measures: [{ as: 'n', fn: 'count' }] }),
    400,
    /bucket must be/,
  );
  refuses(agg({ timezone: 'Mars/Olympus', measures: [{ as: 'n', fn: 'count' }] }), 400, /IANA/);
  refuses(agg({ limit: 10001, measures: [{ as: 'n', fn: 'count' }] }), 400, /limit/);
});

test('aggregate rows are shaped by the caller names, and truncation is reported', () => {
  const spec = parse({
    mode: 'aggregate',
    window: WINDOW,
    group_by: ['event_name'],
    measures: [
      { as: 'events', fn: 'count' },
      { as: 'first', fn: 'min', of: 'created_at' },
    ],
    limit: 1,
  });
  const at = new Date('2026-09-14T07:50:12.345Z');
  const out = shapeAggregate(spec, [
    { g0: 'a', m0: '18', m1: at },
    { g0: 'b', m0: '3', m1: at },
  ]);
  assert.deepEqual(out, {
    columns: ['event_name', 'events', 'first'],
    rows: [{ event_name: 'a', events: 18, first: '2026-09-14T07:50:12.345Z' }],
    truncated: true,
  });
});

test('property values decode by their stored type', () => {
  assert.equal(decodeProp({ data_type: 1, string_value: 'csv' }), 'csv');
  assert.equal(decodeProp({ data_type: 2, number_value: '42.0000', string_value: '42.0000' }), 42);
  assert.equal(decodeProp({ data_type: 3, string_value: 'false' }), false);
  assert.equal(
    decodeProp({ data_type: 4, date_value: new Date('2026-09-14T00:00:00Z') }),
    '2026-09-14T00:00:00.000Z',
  );
  assert.deepEqual(decodeProp({ data_type: 5, string_value: '["a","b"]' }), ['a', 'b']);
  assert.equal(decodeProp({ data_type: 5, string_value: 'not json' }), 'not json');
});

test('a schema name that is not a plain identifier is refused', () => {
  assert.throws(() => tablesFor('umami"; DROP'), /plain identifier/);
  assert.equal(tablesFor(undefined).event, '"public"."website_event"');
});

// --- sessions aggregates, ordering, totals ---------------------------------------

const SESSION_WINDOW = { ...WINDOW, on: 'session_start' };
const placeholdersMatch = ({ text, values }) => {
  const used = new Set([...text.matchAll(/\$(\d+)/g)].map(m => Number(m[1])));
  assert.equal(used.size, values.length, text);
  assert.equal(Math.max(...used), values.length);
};

test('the documented sessions aggregate builds per-session rows once', () => {
  const spec = parse({
    mode: 'aggregate',
    of: 'sessions',
    window: SESSION_WINDOW,
    where: { session_props: [{ key: 'user_email', op: 'not_blank' }] },
    group_by: ['bucket:week', 'session_prop:user_email'],
    bucket: { week_start: 'sunday' },
    measures: [
      { as: 'sessions', fn: 'count' },
      {
        as: 'engaged',
        fn: 'count',
        where: { session_events: { all: ['result.opened', 'source.viewed'] } },
      },
      {
        as: 'avg_duration',
        fn: 'avg',
        of: 'duration_seconds',
        where: { duration_seconds: { between: [30, 480] } },
      },
      { as: 'median', fn: 'percentile', p: 0.5, of: 'duration_seconds' },
      { as: 'cases', fn: 'count_distinct', of: 'session_prop:case_uuid' },
      { as: 'pas', fn: 'values', of: 'session_prop:pa_number', limit: 5 },
      { as: 'drug', fn: 'first', of: 'session_prop:drug_name' },
      { as: 'opened', fn: 'sum', of: 'event_count:result.opened' },
    ],
  });
  const q = buildAggregateSql(spec, SITE, T);
  const { text, values } = q;
  placeholdersMatch(q);
  assert.match(text, /^WITH ss AS MATERIALIZED \(/);
  assert.match(text, /FROM ss CROSS JOIN LATERAL \(SELECT MIN\(e\.created_at\)/);
  // Sessions selected by their start, events still bounded by the window.
  assert.match(text, /s\.website_id = \$1::uuid AND s\.created_at >= \$2 AND s\.created_at < \$3/);
  assert.match(
    text,
    /e\.website_id = ss\.website_id AND e\.session_id = ss\.session_id AND e\.created_at >= \$2 AND e\.created_at < \$3/,
  );
  // One count column per event name, shared by the filter and the sum.
  assert.equal((text.match(/COUNT\(\*\) FILTER \(WHERE e\.event_name = /g) || []).length, 2);
  assert.match(text, /FILTER \(WHERE x\.c0 > 0 AND x\.c1 > 0\)/);
  assert.match(text, /SUM\(x\.c0\)/);
  assert.match(text, /x\.duration_seconds BETWEEN \$\d+ AND \$\d+/);
  assert.match(
    text,
    /percentile_cont\(\$\d+::float8\) WITHIN GROUP \(ORDER BY x\.duration_seconds\)/,
  );
  assert.match(
    text,
    /date_trunc\('week', \(x\.session_start AT TIME ZONE \$\d+\) \+ interval '1 day'\) - interval '1 day'/,
  );
  assert.match(text, /\[1:\$\d+::int\]/);
  assert.match(text, /ORDER BY x\.first_at, x\.session_id\) FILTER/);
  // Session property joins and filters are pinned to the session row's site.
  assert.match(text, /LEFT JOIN "umami"\."session_data" sk0 ON sk0\.website_id = x\.website_id/);
  assert.match(text, /pf\.website_id = s\.website_id AND pf\.session_id = s\.session_id/);
  assert.equal(values[0], SITE);
  assert.ok(values.includes('result.opened') && values.includes(0.5) && values.includes(5));
});

test('a sessions aggregate refuses what belongs to events, and says so', () => {
  const agg = extra => ({
    mode: 'aggregate',
    of: 'sessions',
    window: SESSION_WINDOW,
    measures: [{ as: 'n', fn: 'count' }],
    ...extra,
  });
  refuses(agg({ where: { event_names: ['x'] } }), 400, /cannot filter a sessions aggregate/);
  refuses(agg({ group_by: ['event_name'] }), 400, /not groupable in a sessions aggregate/);
  refuses(
    agg({ measures: [{ as: 'n', fn: 'sum', of: 'event_prop:rows' }] }),
    400,
    /duration_seconds, event_count or event_count:<name>/,
  );
  refuses(
    agg({ group_by: ['bucket:day'], bucket: { on: 'event' } }),
    400,
    /session_start" in a sessions aggregate/,
  );
  refuses(agg({ of: 'visits' }), 400, /of must be/);
  // Event aggregates, in turn, do not know per-session numbers.
  refuses(
    {
      mode: 'aggregate',
      window: WINDOW,
      measures: [{ as: 'n', fn: 'avg', of: 'duration_seconds' }],
    },
    400,
    /numeric property/,
  );
  refuses(
    {
      mode: 'aggregate',
      window: WINDOW,
      where: { duration_seconds: { gte: 1 } },
      measures: [{ as: 'n', fn: 'count' }],
    },
    400,
    /Unknown field "duration_seconds"/,
  );
});

test('measure options are validated', () => {
  const m = measure => ({
    mode: 'aggregate',
    of: 'sessions',
    window: SESSION_WINDOW,
    measures: [measure],
  });
  refuses(
    m({ as: 'p', fn: 'percentile', of: 'duration_seconds' }),
    400,
    /p must be a number from 0 to 1/,
  );
  refuses(m({ as: 'p', fn: 'percentile', p: 1.5, of: 'duration_seconds' }), 400, /0 to 1/);
  refuses(m({ as: 'p', fn: 'count', p: 0.5 }), 400, /only used with "percentile"/);
  refuses(m({ as: 'v', fn: 'values', of: 'session_prop:k', limit: 1001 }), 400, /limit/);
  refuses(
    m({ as: 'v', fn: 'avg', of: 'session_prop:k', limit: 3 }),
    400,
    /only used with "values"/,
  );
  refuses(m({ as: 'f', fn: 'first', of: 'duration_seconds' }), 400, /session_prop:<key>/);
  refuses(
    m({ as: 'n', fn: 'count', where: { duration_seconds: { between: [5, 1] } } }),
    400,
    /low <= high/,
  );
  refuses(
    m({ as: 'n', fn: 'count', where: { duration_seconds: { about: 3 } } }),
    400,
    /Unknown field/,
  );
  refuses(
    m({ as: 'n', fn: 'count', where: { session_events: { some: ['x'] } } }),
    400,
    /Unknown field/,
  );
});

test('event aggregates gain session-property distinct counts, values and first/last', () => {
  const spec = parse({
    mode: 'aggregate',
    window: SESSION_WINDOW,
    where: { event_names: ['case-opened'] },
    group_by: ['bucket:year'],
    bucket: { on: 'session_start' },
    measures: [
      { as: 'cases', fn: 'count_distinct', of: 'session_prop:case_uuid' },
      { as: 'labels', fn: 'values', of: 'event_prop:label' },
      { as: 'last_label', fn: 'last', of: 'event_prop:label' },
      { as: 'p90', fn: 'percentile', p: 0.9, of: 'event_prop:rows' },
    ],
  });
  const q = buildAggregateSql(spec, SITE, T);
  placeholdersMatch(q);
  assert.match(
    q.text,
    /to_char\(date_trunc\('year', \(s\.created_at AT TIME ZONE \$\d+\)\), 'YYYY'\)/,
  );
  assert.match(
    q.text,
    /LEFT JOIN "umami"\."session_data" sk0 ON sk0\.website_id = e\.website_id AND sk0\.session_id = e\.session_id/,
  );
  assert.match(q.text, /ORDER BY e\.created_at DESC, e\.event_id DESC\) FILTER/);
  assert.match(q.text, /NULLIF\(TRIM\(sk0\.string_value\), ''\)/);
});

test('window.on session_start bounds events by both times', () => {
  const spec = parse({ mode: 'events', window: SESSION_WINDOW });
  const { text } = buildEventsSql(spec, SITE, T);
  assert.match(text, / JOIN "umami"\."session" s ON/);
  assert.match(
    text,
    /e\.created_at >= \$2 AND e\.created_at < \$3 AND s\.created_at >= \$4 AND s\.created_at < \$5/,
  );
  refuses({ mode: 'events', window: { ...WINDOW, on: 'visit' } }, 400, /window\.on must be/);
});

test('a sessions page by session start keeps sessions with no events unless events are filtered', () => {
  const plain = parse({ mode: 'sessions', window: SESSION_WINDOW });
  const a = buildSessionsPageSql(plain, SITE, T);
  placeholdersMatch(a);
  assert.match(a.text, /FROM "umami"\."session" s CROSS JOIN LATERAL/);
  assert.doesNotMatch(a.text, /m\.event_count > 0/);
  assert.match(a.text, /ORDER BY s\.created_at, s\.session_id/);

  const filtered = parse({
    mode: 'sessions',
    window: SESSION_WINDOW,
    where: {
      event_names: ['reasoning'],
      session_props: [{ key: 'user_email', op: 'eq', value: 'a@b' }],
    },
    order: [{ field: 'created_at', dir: 'desc' }],
    include_total: true,
  });
  const b = buildSessionsPageSql(filtered, SITE, T);
  placeholdersMatch(b);
  assert.match(b.text, /m\.event_count > 0/);
  assert.match(b.text, /e\.event_name = ANY/);
  assert.match(b.text, /pf\.website_id = s\.website_id AND pf\.session_id = s\.session_id/);
  assert.match(b.text, /COUNT\(\*\) OVER \(\) AS total_count/);
  assert.match(b.text, /ORDER BY s\.created_at DESC, s\.session_id DESC/);
});

test('order and include_total are validated per mode and reach the SQL', () => {
  const ev = parse({
    mode: 'events',
    window: WINDOW,
    order: [{ field: 'created_at', dir: 'desc' }],
    include_total: true,
  });
  const { text } = buildEventsSql(ev, SITE, T);
  assert.match(text, /COUNT\(\*\) OVER \(\) AS total_count/);
  assert.match(text, /ORDER BY e\.created_at DESC, e\.event_id DESC/);
  refuses(
    { mode: 'events', window: WINDOW, order: [{ field: 'name' }] },
    400,
    /field must be one of: created_at/,
  );
  refuses(
    { mode: 'events', window: WINDOW, order: [{ field: 'created_at', dir: 'up' }] },
    400,
    /dir/,
  );
  refuses({ mode: 'events', window: WINDOW, include_total: 'yes' }, 400, /true or false/);

  const agg = parse({
    mode: 'aggregate',
    window: WINDOW,
    group_by: ['event_name'],
    measures: [{ as: 'n', fn: 'count' }],
    order: [{ field: 'n', dir: 'desc' }],
    limit: 10,
    offset: 20,
    include_total: true,
  });
  const q = buildAggregateSql(agg, SITE, T);
  assert.match(q.text, /ORDER BY m0 DESC, 1 LIMIT \$\d+ OFFSET \$\d+$/);
  assert.deepEqual(q.values.slice(-2), [11, 20]);
  refuses(
    {
      mode: 'aggregate',
      window: WINDOW,
      measures: [{ as: 'n', fn: 'count' }],
      order: [{ field: 'x' }],
    },
    400,
    /field must be one of: n/,
  );
});

test('contains, not_blank and event_names_not_in keep caller text out of SQL', () => {
  const evil = "a%_'; DROP TABLE session; --";
  const spec = parse({
    mode: 'events',
    window: WINDOW,
    where: {
      event_names_not_in: [evil],
      session_props: [
        { key: 'drug_name', op: 'contains', value: evil, case: 'insensitive' },
        { key: 'user_email', op: 'not_blank' },
      ],
      event_props: [{ key: 'label', op: 'contains', value: evil }],
    },
  });
  const q = buildEventsSql(spec, SITE, T);
  placeholdersMatch(q);
  assert.ok(!q.text.includes('DROP'));
  assert.match(q.text, /strpos\(lower\(pf\.string_value\), lower\(\$\d+\)\) > 0/);
  assert.match(q.text, /strpos\(pf\.string_value, \$\d+\) > 0/);
  assert.match(q.text, /COALESCE\(TRIM\(pf\.string_value\), ''\) <> ''/);
  assert.match(q.text, /\(e\.event_name IS NULL OR NOT \(e\.event_name = ANY\(/);
  refuses(
    {
      mode: 'events',
      window: WINDOW,
      where: { event_props: [{ key: 'k', op: 'eq', value: 'v', case: 'insensitive' }] },
    },
    400,
    /only used with op "contains"/,
  );
  refuses(
    {
      mode: 'events',
      window: WINDOW,
      where: { event_props: [{ key: 'k', op: 'not_blank', value: 'v' }] },
    },
    400,
    /not used with op "not_blank"/,
  );
});

test('session properties on event rows are opt-in', () => {
  assert.deepEqual(parse({ mode: 'events', window: WINDOW }).sessionProps, { none: true });
  assert.deepEqual(
    parse({ mode: 'events', window: WINDOW, select: { session_props: ['case_uuid'] } })
      .sessionProps,
    { keys: ['case_uuid'] },
  );
});

test('aggregate shaping reports cut value lists, totals and the offset', () => {
  const spec = parse({
    mode: 'aggregate',
    of: 'sessions',
    window: SESSION_WINDOW,
    measures: [
      { as: 'pas', fn: 'values', of: 'session_prop:pa', limit: 2 },
      { as: 'drug', fn: 'first', of: 'session_prop:drug' },
      { as: 'last', fn: 'max', of: 'session_start' },
    ],
    offset: 5,
    include_total: true,
  });
  const at = new Date('2026-09-14T07:50:12.345Z');
  const out = shapeAggregate(spec, [
    { m0: ['PA-1', 'PA-2'], m0n: '3', m1: 42, m2: at, total_count: '9' },
  ]);
  assert.deepEqual(out.rows, [
    { pas: ['PA-1', 'PA-2'], drug: 42, last: '2026-09-14T07:50:12.345Z' },
  ]);
  assert.deepEqual(out.values_truncated, ['pas']);
  assert.equal(out.total, 9);
  assert.equal(out.offset, 5);
  assert.deepEqual(
    shapeAggregate(spec, [{ m0: null, m0n: '0', m1: null, m2: null, total_count: '1' }]).rows,
    [{ pas: [], drug: null, last: null }],
  );
});
