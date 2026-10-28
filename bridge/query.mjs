/**
 * The app-facing query API: structured JSON in, parameterized read-only SQL out.
 *
 * WHY THIS IS NOT A SQL ENDPOINT
 *
 * A caller describes WHAT it wants -- a mode, a window, filters, fields -- and
 * this module decides HOW to ask for it. Every column, table and operator below
 * comes from a fixed list in this file; every value the caller sends travels as
 * a bind parameter. Nothing a caller writes is ever spliced into SQL text, so
 * there is no statement for a caller to inject into, including the
 * `SET TRANSACTION READ WRITE` that would undo the read-only transaction the
 * handler wraps around every query (see db.mjs).
 *
 * WHAT IS DELIBERATELY ABSENT, AND WHY
 *
 * Page titles, query strings (url_query, referrer_query), referrer paths,
 * `distinct_id` and the ad click ids are not selectable, filterable or
 * groupable. In a healthcare app a tab title carries a name as readily as a URL
 * does, a query string is the likeliest place for a search term or a member
 * number, and `distinct_id` identifies a person. The collector strips most of
 * them on the way in; handing them back on the way out would undo that for any
 * site instrumented some other way, such as with Umami's own script.js.
 *
 * WHAT A REQUEST CAN ASK FOR
 *
 * Three modes over one site and one window:
 *   events     matching events, paged, with their properties and optionally
 *              their session's properties
 *   sessions   matching sessions, paged, optionally with their events nested
 *   aggregate  groups and measures, over events or -- with `of: "sessions"` --
 *              over sessions, each carrying its duration and event counts
 * The window selects by event time, or with `on: "session_start"` by when the
 * session began. Every name an app cares about (event names, property keys,
 * duration bounds) is a parameter, so one app's dashboard is a set of requests
 * here rather than endpoints of its own.
 *
 * THE SITE IS NOT A PARAMETER OF THE REQUEST BODY
 *
 * It comes from the path, which genesis-authz has already checked against
 * `umami_site can_view` before this process is reached. Every statement built
 * here filters on it -- in the outer query AND inside every property subquery --
 * so a request can never widen to another site's rows, whatever its body says.
 */

export class QueryError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const bad = message => new QueryError(400, message);

/** Umami's stored event_type, by number. */
export const EVENT_TYPE_NAMES = {
  1: 'pageview',
  2: 'custom',
  3: 'link',
  4: 'pixel',
  5: 'performance',
};

/** The two values `where.event_type` narrows to; `any` means no filter. */
const EVENT_TYPE_FILTER = { pageview: 1, custom: 2 };

/** Umami's stored data_type, by number (DATA_TYPE in src/lib/constants.ts). */
export const DATA_TYPE_NAMES = {
  1: 'string',
  2: 'number',
  3: 'boolean',
  4: 'date',
  5: 'array',
};

/** Event fields a caller may select, and the column behind each. */
const EVENT_FIELDS = {
  id: 'event_id',
  session_id: 'session_id',
  visit_id: 'visit_id',
  created_at: 'created_at',
  type: 'event_type',
  name: 'event_name',
  url_path: 'url_path',
  hostname: 'hostname',
  referrer_domain: 'referrer_domain',
};

/** Session fields a caller may select. `id` is session_id. */
const SESSION_FIELDS = [
  'id',
  'created_at',
  'browser',
  'os',
  'device',
  'screen',
  'language',
  'country',
  'region',
  'city',
];

/** Session fields a caller may filter and group on (exact match). */
const SESSION_FILTER_FIELDS = [
  'browser',
  'os',
  'device',
  'screen',
  'language',
  'country',
  'region',
  'city',
];

const PROP_OPS = new Set([
  'eq',
  'neq',
  'in',
  'not_in',
  'exists',
  'not_exists',
  'starts_with',
  'contains',
  'not_blank',
]);

/**
 * neq, not_in and not_exists are the negations of eq, in and exists -- so an
 * event WITHOUT the key matches all three. "format is not csv" therefore keeps
 * events that carry no format at all, which is what a filter that excludes
 * something should mean.
 */
const NEGATED_OPS = { neq: 'eq', not_in: 'in', not_exists: 'exists' };

const BUCKETS = {
  hour: `'YYYY-MM-DD"T"HH24:00'`,
  day: `'YYYY-MM-DD'`,
  // date_trunc('week') starts on Monday (ISO), so the label is that Monday.
  week: `'YYYY-MM-DD'`,
  month: `'YYYY-MM'`,
  year: `'YYYY'`,
};

/**
 * What the window's from/to select on. `event` (the default): events whose own
 * time is in the window. `session_start`: sessions that STARTED in the window,
 * and of those only their events that are also in it -- so a session that began
 * before the window is left out even if it was active inside it.
 */
const WINDOW_ON = ['event', 'session_start'];

/**
 * What a sessions aggregate computes for each session, over that session's
 * events inside the window:
 *   duration_seconds  last event minus first; 0 for a session with one event or none
 *   event_count       how many events; event_count:<name> counts one event name
 *   session_start     session.created_at
 *   first_at/last_at  first/last event, or session_start for a session with none
 */
const SESSION_NUMBERS = ['duration_seconds', 'event_count'];
const SESSION_TIMES = ['session_start', 'first_at', 'last_at'];

const RANGE_OPS = ['between', 'not_between', 'gte', 'gt', 'lte', 'lt'];

/** Distinct values one `values` measure returns per row, by default and at most. */
const VALUES_DEFAULT = 100;
const VALUES_MAX = 1000;

const MEASURE_NAME_RE = /^[a-z_][a-z0-9_]{0,62}$/;
const SCHEMA_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;

// Bounds on the SHAPE of a request, not on the data it reads. They keep one
// body from compiling into a statement Postgres has to plan for seconds.
const MAX_LIST = 100;
const MAX_PROP_FILTERS = 20;
const MAX_GROUP_BY = 5;
const MAX_MEASURES = 10;
const MAX_TEXT = 500;
const MAX_PAGE_NUMBER = 1_000_000;
const MAX_ORDER = 5;
const MAX_OFFSET = 10_000_000;

/** Fully qualified table names for one Postgres schema. */
export function tablesFor(schema) {
  const name = schema || 'public';
  if (!SCHEMA_NAME_RE.test(name)) {
    throw new Error(`Database schema name ${JSON.stringify(name)} is not a plain identifier.`);
  }
  const q = table => `"${name}"."${table}"`;
  return {
    event: q('website_event'),
    eventData: q('event_data'),
    session: q('session'),
    sessionData: q('session_data'),
  };
}

// --- validation helpers ------------------------------------------------------

const isObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);

function onlyKeys(obj, allowed, where) {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) {
      throw bad(`Unknown field "${key}" in ${where}. Allowed: ${allowed.join(', ')}.`);
    }
  }
}

function text(value, where) {
  if (typeof value !== 'string' || !value || value.length > MAX_TEXT) {
    throw bad(`${where} must be a non-empty string of at most ${MAX_TEXT} characters.`);
  }
  return value;
}

function textList(value, where) {
  if (!Array.isArray(value) || !value.length || value.length > MAX_LIST) {
    throw bad(`${where} must be a non-empty list of at most ${MAX_LIST} strings.`);
  }
  return value.map((v, i) => text(v, `${where}[${i}]`));
}

function scalar(value, where) {
  const type = typeof value;
  if (type === 'string') return text(value, where);
  if (type === 'number' && Number.isFinite(value)) return value;
  if (type === 'boolean') return value;
  throw bad(`${where} must be a string, a finite number or a boolean.`);
}

function intIn(value, min, max, where) {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw bad(`${where} must be a whole number from ${min} to ${max}.`);
  }
  return value;
}

/** Escape LIKE's wildcards so `starts_with` matches the caller's text literally. */
const likePrefix = value => `${value.replace(/[\\%_]/g, c => `\\${c}`)}%`;

// --- window ------------------------------------------------------------------

/**
 * Resolve `from`/`to` to two Dates. Epoch milliseconds or anything Date can
 * parse. `from` inclusive, `to` exclusive.
 *
 * No cap on the width: whatever range the caller sends is answered. What bounds
 * the cost instead is the statement timeout (db.mjs) and the page and row
 * limits below.
 */
export function parseWindow(rawFrom, rawTo, prefix = 'window.') {
  const parse = (raw, name) => {
    if (raw === undefined || raw === null || raw === '') {
      throw new QueryError(422, `${prefix}${name} is required.`);
    }
    const asNumber = typeof raw === 'number' ? raw : Number(raw);
    const ms =
      typeof raw === 'number' ||
      (Number.isFinite(asNumber) && String(asNumber) === String(raw).trim())
        ? asNumber
        : Date.parse(raw);
    // A finite number can still be past the range a Date holds (about 275,000
    // years either side of 1970), which would reach Postgres as an invalid
    // timestamp and come back as a generic 502 instead of this 422.
    const date = new Date(ms);
    if (!Number.isFinite(ms) || Number.isNaN(date.getTime())) {
      throw new QueryError(422, `${prefix}${name} must be epoch milliseconds or an ISO 8601 date.`);
    }
    return date;
  };
  const from = parse(rawFrom, 'from');
  const to = parse(rawTo, 'to');
  if (from >= to) throw new QueryError(422, `${prefix}from must be earlier than ${prefix}to.`);
  return { from, to };
}

// --- where -------------------------------------------------------------------

function parsePropFilters(list, where) {
  if (!Array.isArray(list) || !list.length || list.length > MAX_PROP_FILTERS) {
    throw bad(`${where} must be a non-empty list of at most ${MAX_PROP_FILTERS} filters.`);
  }
  return list.map((f, i) => {
    const at = `${where}[${i}]`;
    if (!isObject(f)) throw bad(`${at} must be an object with key, op and value.`);
    onlyKeys(f, ['key', 'op', 'value', 'case'], at);
    const key = text(f.key, `${at}.key`);
    const op = f.op;
    if (!PROP_OPS.has(op)) {
      throw bad(`${at}.op must be one of: ${[...PROP_OPS].join(', ')}.`);
    }
    if (f.case !== undefined && op !== 'contains') {
      throw bad(`${at}.case is only used with op "contains".`);
    }
    if (op === 'contains') {
      if (f.case !== undefined && f.case !== 'sensitive' && f.case !== 'insensitive') {
        throw bad(`${at}.case must be "sensitive" or "insensitive".`);
      }
      return {
        key,
        op,
        value: text(f.value, `${at}.value`),
        insensitive: f.case === 'insensitive',
      };
    }
    if (op === 'exists' || op === 'not_exists' || op === 'not_blank') {
      if (f.value !== undefined) throw bad(`${at}.value is not used with op "${op}".`);
      return { key, op };
    }
    if (op === 'in' || op === 'not_in') {
      if (!Array.isArray(f.value) || !f.value.length || f.value.length > MAX_LIST) {
        throw bad(
          `${at}.value must be a non-empty list of at most ${MAX_LIST} values for op "${op}".`,
        );
      }
      const values = f.value.map((v, j) => scalar(v, `${at}.value[${j}]`));
      if (new Set(values.map(v => typeof v)).size > 1) {
        throw bad(`${at}.value must hold values of one type.`);
      }
      return { key, op, value: values };
    }
    if (op === 'starts_with') return { key, op, value: text(f.value, `${at}.value`) };
    return { key, op, value: scalar(f.value, `${at}.value`) };
  });
}

/**
 * Validate a `where` object. Used for the request's own filter and for each
 * measure's, which is why it takes the path it is reporting errors under.
 */
const EVENT_WHERE_KEYS = [
  'event_type',
  'event_names',
  'event_names_not_in',
  'url_path',
  'hostname',
  'session',
  'event_props',
  'session_props',
];

/**
 * A sessions aggregate filters whole sessions, so it takes what describes a
 * session -- its fields, its properties, its duration and which events it had --
 * and refuses event filters, which would leave it unclear whether a session's
 * duration covers all its events or only the matching ones.
 */
const SESSION_WHERE_KEYS = ['session', 'session_props', 'duration_seconds', 'session_events'];

function parseRange(value, at) {
  if (!isObject(value) || !Object.keys(value).length) {
    throw bad(`${at} must be an object with one or more of: ${RANGE_OPS.join(', ')}.`);
  }
  onlyKeys(value, RANGE_OPS, at);
  const num = (v, where) => {
    if (typeof v !== 'number' || !Number.isFinite(v)) throw bad(`${where} must be a number.`);
    return v;
  };
  const out = {};
  for (const op of ['between', 'not_between']) {
    if (value[op] === undefined) continue;
    const pair = value[op];
    if (!Array.isArray(pair) || pair.length !== 2) {
      throw bad(`${at}.${op} must be [low, high].`);
    }
    const [lo, hi] = [num(pair[0], `${at}.${op}[0]`), num(pair[1], `${at}.${op}[1]`)];
    if (lo > hi) throw bad(`${at}.${op} must be [low, high] with low <= high.`);
    out[op] = [lo, hi];
  }
  for (const op of ['gte', 'gt', 'lte', 'lt']) {
    if (value[op] !== undefined) out[op] = num(value[op], `${at}.${op}`);
  }
  return out;
}

function parseSessionEvents(value, at) {
  if (!isObject(value) || !Object.keys(value).length) {
    throw bad(`${at} must be an object with one or more of: all, any, none.`);
  }
  onlyKeys(value, ['all', 'any', 'none'], at);
  const out = {};
  for (const k of ['all', 'any', 'none']) {
    if (value[k] !== undefined) out[k] = textList(value[k], `${at}.${k}`);
  }
  return out;
}

export function parseWhere(where, at = 'where', scope = 'events') {
  if (where === undefined) return {};
  if (!isObject(where)) throw bad(`${at} must be an object.`);
  const allowed = scope === 'sessions' ? SESSION_WHERE_KEYS : EVENT_WHERE_KEYS;
  for (const key of Object.keys(where)) {
    if (!allowed.includes(key)) {
      throw bad(
        scope === 'sessions'
          ? `"${key}" cannot filter a sessions aggregate. ${at} takes: ${allowed.join(', ')}.`
          : `Unknown field "${key}" in ${at}. Allowed: ${allowed.join(', ')}.`,
      );
    }
  }
  const out = {};
  if (where.duration_seconds !== undefined) {
    out.duration = parseRange(where.duration_seconds, `${at}.duration_seconds`);
  }
  if (where.session_events !== undefined) {
    out.sessionEvents = parseSessionEvents(where.session_events, `${at}.session_events`);
  }
  if (where.event_names_not_in !== undefined) {
    out.eventNamesNotIn = textList(where.event_names_not_in, `${at}.event_names_not_in`);
  }
  if (where.event_type !== undefined && where.event_type !== 'any') {
    if (!(where.event_type in EVENT_TYPE_FILTER)) {
      throw bad(`${at}.event_type must be one of: pageview, custom, any.`);
    }
    out.eventType = EVENT_TYPE_FILTER[where.event_type];
  }
  if (where.event_names !== undefined)
    out.eventNames = textList(where.event_names, `${at}.event_names`);
  if (where.url_path !== undefined) {
    const u = where.url_path;
    if (!isObject(u))
      throw bad(`${at}.url_path must be { "op": "eq" | "starts_with", "value": "..." }.`);
    onlyKeys(u, ['op', 'value'], `${at}.url_path`);
    if (u.op !== 'eq' && u.op !== 'starts_with') {
      throw bad(`${at}.url_path.op must be "eq" or "starts_with".`);
    }
    out.urlPath = { op: u.op, value: text(u.value, `${at}.url_path.value`) };
  }
  if (where.hostname !== undefined) out.hostname = text(where.hostname, `${at}.hostname`);
  if (where.session !== undefined) {
    if (!isObject(where.session)) throw bad(`${at}.session must be an object.`);
    onlyKeys(where.session, SESSION_FILTER_FIELDS, `${at}.session`);
    out.session = Object.fromEntries(
      Object.entries(where.session).map(([k, v]) => [k, text(v, `${at}.session.${k}`)]),
    );
  }
  if (where.event_props !== undefined)
    out.eventProps = parsePropFilters(where.event_props, `${at}.event_props`);
  if (where.session_props !== undefined) {
    out.sessionProps = parsePropFilters(where.session_props, `${at}.session_props`);
  }
  return out;
}

const usesSession = w => Boolean(w.session && Object.keys(w.session).length);

// --- SQL building blocks -----------------------------------------------------

/** Positional bind parameters, in the order the SQL text refers to them. */
class Params {
  constructor() {
    this.values = [];
  }
  add(value) {
    this.values.push(value);
    return `$${this.values.length}`;
  }
}

/**
 * The value test for one property filter against a data row aliased `a`.
 *
 * Umami fills string_value for EVERY type (numbers as "42.0000", booleans as
 * "true"/"false", dates as ISO) and number_value / date_value only for their own
 * type. So a string compares on string_value, a number on number_value, and a
 * boolean on its stored text with the type pinned, so `true` never matches a
 * string property that happens to read "true".
 */
function propValueSql(a, op, value, p) {
  if (op === 'exists') return 'TRUE';
  if (op === 'not_blank') return `COALESCE(TRIM(${a}.string_value), '') <> ''`;
  if (op === 'starts_with') return `${a}.string_value LIKE ${p.add(likePrefix(value))} ESCAPE '\\'`;
  if (op === 'contains') {
    // strpos, not LIKE: the caller's text is matched literally, so a % or _ in
    // it needs no escaping.
    return value.insensitive
      ? `strpos(lower(${a}.string_value), lower(${p.add(value.text)})) > 0`
      : `strpos(${a}.string_value, ${p.add(value.text)}) > 0`;
  }
  const values = op === 'in' ? value : [value];
  const type = typeof values[0];
  if (type === 'number') return `${a}.number_value = ANY(${p.add(values)}::numeric[])`;
  if (type === 'boolean') {
    return `(${a}.data_type = 3 AND ${a}.string_value = ANY(${p.add(values.map(String))}::text[]))`;
  }
  return `${a}.string_value = ANY(${p.add(values)}::text[])`;
}

function propFilterSql(table, link, filter, p) {
  const positive = NEGATED_OPS[filter.op] || filter.op;
  const value =
    filter.op === 'contains'
      ? { text: filter.value, insensitive: filter.insensitive }
      : filter.value;
  const exists =
    `EXISTS (SELECT 1 FROM ${table} pf WHERE ${link} ` +
    `AND pf.data_key = ${p.add(filter.key)} ` +
    `AND ${propValueSql('pf', positive, value, p)})`;
  return filter.op in NEGATED_OPS ? `NOT ${exists}` : exists;
}

/**
 * A parsed `where` as SQL conditions over `e` (website_event) and, when a
 * session field is filtered, `s` (session). Every property subquery repeats the
 * site filter, so it uses the (website_id, ...) indexes and can never read a row
 * of another site even if the outer query were ever written without one.
 */
function whereSql(w, p, t) {
  return [...eventConds(w, p, t), ...sessionConds(w, p, t, { fields: 's', link: 'e' })];
}

/** Does this `where` narrow events, as opposed to whole sessions? */
const hasEventFilters = w =>
  Boolean(
    w.eventType ||
      w.eventNames ||
      w.eventNamesNotIn ||
      w.urlPath ||
      w.hostname ||
      w.eventProps?.length,
  );

/** The event half of a `where`, over `e` (website_event). */
function eventConds(w, p, t) {
  const out = [];
  if (w.eventType) out.push(`e.event_type = ${p.add(w.eventType)}`);
  if (w.eventNames) out.push(`e.event_name = ANY(${p.add(w.eventNames)}::text[])`);
  // A negation, like neq: an event with no name at all (a pageview) is kept.
  if (w.eventNamesNotIn) {
    out.push(
      `(e.event_name IS NULL OR NOT (e.event_name = ANY(${p.add(w.eventNamesNotIn)}::text[])))`,
    );
  }
  if (w.urlPath) {
    out.push(
      w.urlPath.op === 'eq'
        ? `e.url_path = ${p.add(w.urlPath.value)}`
        : `e.url_path LIKE ${p.add(likePrefix(w.urlPath.value))} ESCAPE '\\'`,
    );
  }
  if (w.hostname) out.push(`e.hostname = ${p.add(w.hostname)}`);
  for (const f of w.eventProps || []) {
    out.push(
      propFilterSql(
        t.eventData,
        'pf.website_id = e.website_id AND pf.website_event_id = e.event_id',
        f,
        p,
      ),
    );
  }
  return out;
}

/**
 * The session half of a `where`. `fields` is the alias holding the session's
 * columns and `link` the alias whose session_id/website_id the property
 * subqueries join on -- `e` when the query reads events, the session row itself
 * when it reads sessions.
 */
function sessionConds(w, p, t, { fields, link }) {
  const out = [];
  for (const [field, value] of Object.entries(w.session || {})) {
    // `field` is from SESSION_FILTER_FIELDS, never from the caller verbatim.
    out.push(`${fields}.${field} = ${p.add(value)}`);
  }
  for (const f of w.sessionProps || []) {
    out.push(
      propFilterSql(
        t.sessionData,
        `pf.website_id = ${link}.website_id AND pf.session_id = ${link}.session_id`,
        f,
        p,
      ),
    );
  }
  return out;
}

function rangeConds(column, range, p) {
  const out = [];
  if (range.between) {
    out.push(`${column} BETWEEN ${p.add(range.between[0])} AND ${p.add(range.between[1])}`);
  }
  if (range.not_between) {
    out.push(
      `NOT (${column} BETWEEN ${p.add(range.not_between[0])} AND ${p.add(range.not_between[1])})`,
    );
  }
  const cmp = { gte: '>=', gt: '>', lte: '<=', lt: '<' };
  for (const [op, sym] of Object.entries(cmp)) {
    if (range[op] !== undefined) out.push(`${column} ${sym} ${p.add(range[op])}`);
  }
  return out;
}

/**
 * The per-session half of a sessions `where`: duration and which events the
 * session had, over the computed row `x`. `countColumn(name)` names the column
 * holding that session's count of one event name.
 */
function sessionMetricConds(w, p, countColumn) {
  const out = [];
  if (w.duration) out.push(...rangeConds('x.duration_seconds', w.duration, p));
  const ev = w.sessionEvents;
  if (ev?.all) out.push(...ev.all.map(n => `x.${countColumn(n)} > 0`));
  if (ev?.any) out.push(`(${ev.any.map(n => `x.${countColumn(n)} > 0`).join(' OR ')})`);
  if (ev?.none) out.push(...ev.none.map(n => `x.${countColumn(n)} = 0`));
  return out;
}

/** FROM + WHERE shared by every mode: one site, one window, then the filters. */
function baseSql(spec, site, p, t, { session = false, extra = [], joins = '' } = {}) {
  const bySessionStart = spec.window.on === 'session_start';
  const join =
    (session || bySessionStart || usesSession(spec.where)
      ? ` JOIN ${t.session} s ON s.session_id = e.session_id AND s.website_id = e.website_id`
      : '') + joins;
  const conditions = [
    `e.website_id = ${p.add(site)}::uuid`,
    `e.created_at >= ${p.add(spec.window.from)}`,
    `e.created_at < ${p.add(spec.window.to)}`,
    ...(bySessionStart
      ? [`s.created_at >= ${p.add(spec.window.from)}`, `s.created_at < ${p.add(spec.window.to)}`]
      : []),
    ...whereSql(spec.where, p, t),
    ...extra,
  ];
  return `FROM ${t.event} e${join} WHERE ${conditions.join(' AND ')}`;
}

// --- select & page -----------------------------------------------------------

function parseFieldList(value, allowed, at) {
  if (value === undefined) return [...allowed];
  if (!Array.isArray(value) || !value.length) throw bad(`${at} must be a non-empty list.`);
  for (const f of value) {
    if (!allowed.includes(f))
      throw bad(`Unknown field "${f}" in ${at}. Allowed: ${allowed.join(', ')}.`);
  }
  return [...new Set(value)];
}

/**
 * Property keys to return. Omitted means every property (the platform collector
 * sends at most ten per event); `[]` means none, and drops `props` from rows.
 */
function parsePropKeys(value, at) {
  if (value === undefined) return { all: true };
  if (!Array.isArray(value) || value.length > MAX_LIST) {
    throw bad(`${at} must be a list of at most ${MAX_LIST} property keys.`);
  }
  if (!value.length) return { none: true };
  return { keys: value.map((k, i) => text(k, `${at}[${i}]`)) };
}

function parsePage(page, maxSize, defaultSize) {
  if (page === undefined) return { number: 1, size: defaultSize };
  if (!isObject(page)) throw bad('page must be an object with number and size.');
  onlyKeys(page, ['number', 'size'], 'page');
  return {
    number: page.number === undefined ? 1 : intIn(page.number, 1, MAX_PAGE_NUMBER, 'page.number'),
    size: page.size === undefined ? defaultSize : intIn(page.size, 1, maxSize, 'page.size'),
  };
}

/**
 * `order`: a list of { field, dir }. `fields` is what this mode may sort on;
 * every list gets a stable tie-break from its builder, so equal values never
 * shuffle between pages.
 */
function parseOrder(value, fields, at, max = 1) {
  if (value === undefined) return null;
  if (!Array.isArray(value) || !value.length || value.length > max) {
    throw bad(`${at} must be a list of 1 to ${max} { field, dir } entries.`);
  }
  return value.map((o, i) => {
    const where = `${at}[${i}]`;
    if (!isObject(o)) throw bad(`${where} must be an object with field and dir.`);
    onlyKeys(o, ['field', 'dir'], where);
    if (!fields.includes(o.field)) {
      throw bad(`${where}.field must be one of: ${fields.join(', ')}.`);
    }
    if (o.dir !== undefined && o.dir !== 'asc' && o.dir !== 'desc') {
      throw bad(`${where}.dir must be "asc" or "desc".`);
    }
    return { field: o.field, desc: o.dir === 'desc' };
  });
}

function parseFlag(value, at) {
  if (value === undefined) return false;
  if (typeof value !== 'boolean') throw bad(`${at} must be true or false.`);
  return value;
}

/** Fields a sessions page may sort on. `created_at` is when the session started. */
const SESSION_ORDER_FIELDS = ['first_at', 'last_at', 'created_at', 'event_count'];

// --- request -----------------------------------------------------------------

const MODE_PARTS = {
  events: ['mode', 'window', 'where', 'select', 'page', 'order', 'include_total'],
  sessions: ['mode', 'window', 'where', 'select', 'page', 'order', 'include_total'],
  aggregate: [
    'mode',
    'of',
    'window',
    'where',
    'timezone',
    'bucket',
    'group_by',
    'measures',
    'order',
    'limit',
    'offset',
    'include_total',
  ],
};

/**
 * Validate a whole POST /query body. Every refusal names the part at fault, and
 * a part the mode does not use is refused rather than ignored, so a caller who
 * sends `page` to an aggregate learns that it did nothing.
 */
export function parseQueryRequest(body, limits) {
  if (!isObject(body)) throw bad('The request body must be a JSON object.');
  const parts = MODE_PARTS[body.mode];
  if (!parts) throw bad('mode must be one of: events, sessions, aggregate.');
  for (const key of Object.keys(body)) {
    if (!parts.includes(key)) {
      throw bad(`"${key}" is not used by mode "${body.mode}". It takes: ${parts.join(', ')}.`);
    }
  }
  if (!isObject(body.window))
    throw new QueryError(422, 'window must be an object with from and to.');
  onlyKeys(body.window, ['from', 'to', 'on'], 'window');
  if (body.window.on !== undefined && !WINDOW_ON.includes(body.window.on)) {
    throw bad(`window.on must be one of: ${WINDOW_ON.join(', ')}.`);
  }

  const ofSessions = body.mode === 'aggregate' && body.of === 'sessions';
  const spec = {
    mode: body.mode,
    window: {
      ...parseWindow(body.window.from, body.window.to),
      on: body.window.on || 'event',
    },
    where: parseWhere(body.where, 'where', ofSessions ? 'sessions' : 'events'),
    includeTotal: parseFlag(body.include_total, 'include_total'),
  };

  if (body.mode === 'events') {
    const select = body.select === undefined ? {} : body.select;
    if (!isObject(select)) throw bad('select must be an object.');
    onlyKeys(select, ['event_fields', 'event_props', 'session_props'], 'select');
    spec.eventFields = parseFieldList(
      select.event_fields,
      Object.keys(EVENT_FIELDS),
      'select.event_fields',
    );
    spec.eventProps = parsePropKeys(select.event_props, 'select.event_props');
    // Unlike event_props, omitted means none: most event lists do not want them,
    // and they cost a second lookup.
    spec.sessionProps =
      select.session_props === undefined
        ? { none: true }
        : parsePropKeys(select.session_props, 'select.session_props');
    spec.order = parseOrder(body.order, ['created_at'], 'order') || [
      { field: 'created_at', desc: false },
    ];
    spec.page = parsePage(body.page, limits.maxEventsPage, Math.min(100, limits.maxEventsPage));
  } else if (body.mode === 'sessions') {
    const select = body.select === undefined ? {} : body.select;
    if (!isObject(select)) throw bad('select must be an object.');
    onlyKeys(
      select,
      ['session_fields', 'session_props', 'include_events', 'event_fields', 'event_props'],
      'select',
    );
    if (select.include_events !== undefined && typeof select.include_events !== 'boolean') {
      throw bad('select.include_events must be true or false.');
    }
    spec.includeEvents = select.include_events === true;
    if (
      !spec.includeEvents &&
      (select.event_fields !== undefined || select.event_props !== undefined)
    ) {
      throw bad('select.event_fields and select.event_props need select.include_events: true.');
    }
    spec.sessionFields = parseFieldList(
      select.session_fields,
      SESSION_FIELDS,
      'select.session_fields',
    );
    spec.sessionProps = parsePropKeys(select.session_props, 'select.session_props');
    spec.eventFields = parseFieldList(
      select.event_fields,
      Object.keys(EVENT_FIELDS),
      'select.event_fields',
    );
    spec.eventProps = parsePropKeys(select.event_props, 'select.event_props');
    spec.order = parseOrder(body.order, SESSION_ORDER_FIELDS, 'order') || [
      { field: spec.window.on === 'session_start' ? 'created_at' : 'first_at', desc: false },
    ];
    spec.page = parsePage(body.page, limits.maxSessionsPage, Math.min(50, limits.maxSessionsPage));
  } else {
    Object.assign(spec, parseAggregate(body, limits));
  }
  return spec;
}

// --- aggregate ---------------------------------------------------------------
//
// An aggregate is over events (the default) or, with `of: "sessions"`, over
// sessions: one row per session carrying its duration, its event counts and
// its fields, and the groups and measures run over those rows. Which scope a
// request is in decides what it may group on, measure and filter by -- and a
// name that belongs to the other scope is refused with a message saying so.

const EVENT_GROUP_FIELDS = ['event_name', 'event_type', 'url_path', 'hostname'];

function parseGroup(token, i, scope) {
  const at = `group_by[${i}]`;
  if (typeof token !== 'string') throw bad(`${at} must be a string.`);
  if (token.startsWith('bucket:')) {
    const unit = token.slice('bucket:'.length);
    if (!(unit in BUCKETS))
      throw bad(`${at}: bucket must be one of ${Object.keys(BUCKETS).join(', ')}.`);
    return { kind: 'bucket', unit, name: 'bucket' };
  }
  if (scope === 'events' && EVENT_GROUP_FIELDS.includes(token)) {
    return { kind: 'event', field: token, name: token };
  }
  if (token.startsWith('session:')) {
    const field = token.slice('session:'.length);
    if (!SESSION_FILTER_FIELDS.includes(field)) {
      throw bad(`${at}: session field must be one of ${SESSION_FILTER_FIELDS.join(', ')}.`);
    }
    return { kind: 'session', field, name: token };
  }
  const kinds = scope === 'events' ? ['event_prop', 'session_prop'] : ['session_prop'];
  for (const kind of kinds) {
    if (token.startsWith(`${kind}:`)) {
      return { kind, key: text(token.slice(kind.length + 1), `${at} key`), name: token };
    }
  }
  throw bad(
    scope === 'events'
      ? `${at} "${token}" is not groupable. Use bucket:<${Object.keys(BUCKETS).join('|')}>, ` +
          'event_name, event_type, url_path, hostname, session:<field>, event_prop:<key> or ' +
          'session_prop:<key>.'
      : `${at} "${token}" is not groupable in a sessions aggregate. Use ` +
          `bucket:<${Object.keys(BUCKETS).join('|')}>, session:<field> or session_prop:<key>.`,
  );
}

/**
 * What a measure's `of` names, resolved for its scope:
 *   { type: 'prop', kind, key }        an event or session property
 *   { type: 'number', column }         a per-session number (sessions scope)
 *   { type: 'count', name }            event_count:<name> (sessions scope)
 *   { type: 'time', column }           a timestamp
 *   { type: 'id', column }             session_id / visit_id (events scope)
 */
function parseTarget(of, at, scope) {
  if (typeof of !== 'string') return null;
  const kinds = scope === 'events' ? ['event_prop', 'session_prop'] : ['session_prop'];
  for (const kind of kinds) {
    if (of.startsWith(`${kind}:`)) {
      return { type: 'prop', kind, key: text(of.slice(kind.length + 1), `${at} key`) };
    }
  }
  if (scope === 'events') {
    if (of === 'session_id' || of === 'visit_id') return { type: 'id', column: of };
    if (of === 'created_at') return { type: 'time', column: 'created_at' };
    return null;
  }
  if (SESSION_NUMBERS.includes(of)) return { type: 'number', column: of };
  if (of.startsWith('event_count:')) {
    return { type: 'count', name: text(of.slice('event_count:'.length), `${at} event name`) };
  }
  if (SESSION_TIMES.includes(of)) return { type: 'time', column: of };
  return null;
}

/** What each fn accepts as `of`, per scope -- also the text of its refusal. */
const MEASURE_TARGETS = {
  events: {
    count_distinct: [
      ['id', 'prop'],
      'session_id, visit_id, event_prop:<key> or session_prop:<key>',
    ],
    sum: [['eventNumber'], 'event_prop:<key> (a numeric property)'],
    avg: [['eventNumber'], 'event_prop:<key> (a numeric property)'],
    percentile: [['eventNumber'], 'event_prop:<key> (a numeric property)'],
    min: [['time', 'eventNumber'], 'created_at or event_prop:<key> (a numeric property)'],
    max: [['time', 'eventNumber'], 'created_at or event_prop:<key> (a numeric property)'],
    values: [['prop'], 'event_prop:<key> or session_prop:<key>'],
    first: [['prop'], 'event_prop:<key> or session_prop:<key>'],
    last: [['prop'], 'event_prop:<key> or session_prop:<key>'],
  },
  sessions: {
    count_distinct: [['prop'], 'session_prop:<key>'],
    sum: [['number', 'count'], 'duration_seconds, event_count or event_count:<name>'],
    avg: [['number', 'count'], 'duration_seconds, event_count or event_count:<name>'],
    percentile: [['number', 'count'], 'duration_seconds, event_count or event_count:<name>'],
    min: [
      ['number', 'count', 'time'],
      'duration_seconds, event_count, event_count:<name>, session_start, first_at or last_at',
    ],
    max: [
      ['number', 'count', 'time'],
      'duration_seconds, event_count, event_count:<name>, session_start, first_at or last_at',
    ],
    values: [['prop'], 'session_prop:<key>'],
    first: [['prop'], 'session_prop:<key>'],
    last: [['prop'], 'session_prop:<key>'],
  },
};

const MEASURE_FNS = ['count', ...Object.keys(MEASURE_TARGETS.events)];

function parseMeasure(m, i, scope) {
  const at = `measures[${i}]`;
  if (!isObject(m)) throw bad(`${at} must be an object with as and fn.`);
  onlyKeys(m, ['as', 'fn', 'of', 'where', 'p', 'limit'], at);
  if (typeof m.as !== 'string' || !MEASURE_NAME_RE.test(m.as)) {
    throw bad(
      `${at}.as must be lowercase letters, digits and underscores, starting with a letter.`,
    );
  }
  if (!MEASURE_FNS.includes(m.fn)) throw bad(`${at}.fn must be one of: ${MEASURE_FNS.join(', ')}.`);
  if (m.p !== undefined && m.fn !== 'percentile')
    throw bad(`${at}.p is only used with "percentile".`);
  if (m.limit !== undefined && m.fn !== 'values')
    throw bad(`${at}.limit is only used with "values".`);
  const out = { as: m.as, fn: m.fn, where: parseWhere(m.where, `${at}.where`, scope) };

  if (m.fn === 'count') {
    if (m.of !== undefined) throw bad(`${at}.of is not used with fn "count".`);
    out.kind = 'number';
    return out;
  }

  const [accepts, described] = MEASURE_TARGETS[scope][m.fn];
  const target = parseTarget(m.of, `${at}.of`, scope);
  // An event property counts as a number only where a number is asked for.
  const type =
    target?.type === 'prop' && target.kind === 'event_prop' && accepts.includes('eventNumber')
      ? 'eventNumber'
      : target?.type;
  if (!target || !accepts.includes(type)) {
    throw bad(`${at}.of must be ${described} for fn "${m.fn}".`);
  }
  out.target = target;

  if (m.fn === 'percentile') {
    if (typeof m.p !== 'number' || !(m.p >= 0 && m.p <= 1)) {
      throw bad(`${at}.p must be a number from 0 to 1 (0.5 is the median).`);
    }
    out.p = m.p;
  }
  if (m.fn === 'values') {
    out.limit =
      m.limit === undefined ? VALUES_DEFAULT : intIn(m.limit, 1, VALUES_MAX, `${at}.limit`);
    out.kind = 'list';
  } else if (m.fn === 'first' || m.fn === 'last') {
    out.kind = 'value';
  } else if ((m.fn === 'min' || m.fn === 'max') && target.type === 'time') {
    out.kind = 'time';
  } else {
    out.kind = 'number';
  }
  return out;
}

function parseBucketOptions(value, scope) {
  const out = { weekStart: 'monday', on: scope === 'sessions' ? 'session_start' : 'event' };
  if (value === undefined) return out;
  if (!isObject(value)) throw bad('bucket must be an object with week_start and/or on.');
  onlyKeys(value, ['week_start', 'on'], 'bucket');
  if (value.week_start !== undefined) {
    if (value.week_start !== 'monday' && value.week_start !== 'sunday') {
      throw bad('bucket.week_start must be "monday" or "sunday".');
    }
    out.weekStart = value.week_start;
  }
  if (value.on !== undefined) {
    if (!WINDOW_ON.includes(value.on)) {
      throw bad(`bucket.on must be one of: ${WINDOW_ON.join(', ')}.`);
    }
    // A session is one row, placed at its start; there is no event time to use.
    if (scope === 'sessions' && value.on !== 'session_start') {
      throw bad('bucket.on must be "session_start" in a sessions aggregate.');
    }
    out.on = value.on;
  }
  return out;
}

function parseAggregate(body, limits) {
  if (body.of !== undefined && body.of !== 'events' && body.of !== 'sessions') {
    throw bad('of must be "events" or "sessions".');
  }
  const scope = body.of === 'sessions' ? 'sessions' : 'events';
  let timezone = 'UTC';
  if (body.timezone !== undefined) {
    timezone = text(body.timezone, 'timezone');
    try {
      // Validated here as well as by Postgres, so a typo is a named 400 rather
      // than a database error.
      new Intl.DateTimeFormat('en-US', { timeZone: timezone });
    } catch {
      throw bad(`timezone "${timezone}" is not an IANA time zone name.`);
    }
  }
  const groupBy = body.group_by === undefined ? [] : body.group_by;
  if (!Array.isArray(groupBy) || groupBy.length > MAX_GROUP_BY) {
    throw bad(`group_by must be a list of at most ${MAX_GROUP_BY} entries.`);
  }
  const groups = groupBy.map((g, i) => parseGroup(g, i, scope));
  const names = groups.map(g => g.name);
  if (new Set(names).size !== names.length) throw bad('group_by lists the same grouping twice.');
  const bucket = parseBucketOptions(body.bucket, scope);
  if (body.bucket !== undefined && !groups.some(g => g.kind === 'bucket')) {
    throw bad('bucket options need a bucket:<unit> entry in group_by.');
  }

  if (
    !Array.isArray(body.measures) ||
    !body.measures.length ||
    body.measures.length > MAX_MEASURES
  ) {
    throw bad(`measures must be a non-empty list of at most ${MAX_MEASURES} entries.`);
  }
  const measures = body.measures.map((m, i) => parseMeasure(m, i, scope));
  for (const m of measures) {
    if (names.includes(m.as)) throw bad(`measure name "${m.as}" is already used.`);
    names.push(m.as);
  }

  const limit =
    body.limit === undefined
      ? Math.min(1000, limits.maxAggregateRows)
      : intIn(body.limit, 1, limits.maxAggregateRows, 'limit');
  const offset = body.offset === undefined ? 0 : intIn(body.offset, 0, MAX_OFFSET, 'offset');
  const order = parseOrder(body.order, names, 'order', MAX_ORDER);
  return { scope, timezone, bucket, groups, measures, limit, offset, order };
}

/**
 * A data row's value as jsonb, by its stored type, so a grouped number stays a
 * number in the response and a boolean stays a boolean. Text is trimmed and
 * blank text is no value at all: grouping, distinct counts, `values` and
 * `first` all treat " " and "" like a missing property.
 */
const typedValueSql = a =>
  `CASE ${a}.data_type WHEN 2 THEN to_jsonb(${a}.number_value) ` +
  `WHEN 3 THEN to_jsonb(${a}.string_value = 'true') ` +
  `WHEN 4 THEN to_jsonb(${a}.date_value) ` +
  `ELSE to_jsonb(NULLIF(TRIM(${a}.string_value), '')) END`;

const EVENT_TYPE_LABEL_SQL = `CASE e.event_type ${Object.entries(EVENT_TYPE_NAMES)
  .map(([n, name]) => `WHEN ${n} THEN '${name}'`)
  .join(' ')} END`;

/** One time bucket's label, in the request's time zone. */
function bucketSql(unit, column, spec, p) {
  const local = `(${column} AT TIME ZONE ${p.add(spec.timezone)})`;
  // date_trunc('week') starts weeks on Monday. A Sunday week is the Monday week
  // of the day after, moved back a day -- so Sunday opens its own week.
  const start =
    unit === 'week' && spec.bucket.weekStart === 'sunday'
      ? `(date_trunc('week', ${local} + interval '1 day') - interval '1 day')`
      : `date_trunc('${unit}', ${local})`;
  return `to_char(${start}, ${BUCKETS[unit]})`;
}

/**
 * The SELECT list, joins and ORDER BY shared by both scopes. `ctx` says how the
 * scope reaches things: the alias property joins hang off, where a timestamp
 * lives, how a measure's `where` becomes SQL, and what `first` orders by.
 */
function aggregateParts(spec, p, t, ctx) {
  const joins = [];
  const propAlias = { event_prop: new Map(), session_prop: new Map() };
  // One LEFT JOIN per distinct property key, shared by every grouping and
  // measure that names it. Umami stores one row per key per event (and per
  // session), so the join never multiplies rows.
  const aliasFor = (kind, key) => {
    const map = propAlias[kind];
    if (!map.has(key)) {
      const alias = `${kind === 'event_prop' ? 'ek' : 'sk'}${map.size}`;
      map.set(key, alias);
      joins.push({ kind, key, alias });
    }
    return map.get(key);
  };

  const selects = spec.groups.map((g, i) => {
    let expr;
    if (g.kind === 'bucket') expr = bucketSql(g.unit, ctx.bucketColumn, spec, p);
    else if (g.kind === 'event') {
      expr = g.field === 'event_type' ? EVENT_TYPE_LABEL_SQL : `e.${g.field}`;
    } else if (g.kind === 'session') expr = `${ctx.sessionFields}.${g.field}`;
    else expr = typedValueSql(aliasFor(g.kind, g.key));
    return `${expr} AS g${i}`;
  });

  spec.measures.forEach((m, i) => {
    const conditions = ctx.measureConds(m.where);
    const filterOf = (...more) => {
      const all = [...more, ...conditions];
      return all.length ? ` FILTER (WHERE ${all.join(' AND ')})` : '';
    };
    const target = m.target;
    const value = target?.type === 'prop' ? typedValueSql(aliasFor(target.kind, target.key)) : null;
    const numeric =
      target?.type === 'prop'
        ? `${aliasFor(target.kind, target.key)}.number_value`
        : target && ctx.column(target);
    let expr;
    switch (m.fn) {
      case 'count':
        expr = `COUNT(*)${filterOf()}`;
        break;
      case 'count_distinct':
        expr = `COUNT(DISTINCT ${value ?? ctx.column(target)})${filterOf()}`;
        break;
      case 'sum':
      case 'avg':
      case 'min':
      case 'max':
        expr = `${m.fn.toUpperCase()}(${numeric})${filterOf()}`;
        break;
      case 'percentile':
        expr = `percentile_cont(${p.add(m.p)}::float8) WITHIN GROUP (ORDER BY ${numeric})${filterOf()}`;
        break;
      case 'values':
        // Sorted, distinct and capped in SQL, so a group with a thousand values
        // never crosses the wire whole. The count beside it says when it was cut.
        expr =
          `to_jsonb((array_agg(DISTINCT ${value} ORDER BY ${value})` +
          `${filterOf(`${value} IS NOT NULL`)})[1:${p.add(m.limit)}::int])`;
        selects.push(`COUNT(DISTINCT ${value})${filterOf()} AS m${i}n`);
        break;
      case 'first':
      case 'last': {
        const dir = m.fn === 'last' ? ' DESC' : '';
        const order = ctx.firstOrder.map(c => `${c}${dir}`).join(', ');
        expr = `(array_agg(${value} ORDER BY ${order})${filterOf(`${value} IS NOT NULL`)})[1]`;
        break;
      }
    }
    selects.push(`${expr} AS m${i}`);
  });

  if (spec.includeTotal) selects.push('COUNT(*) OVER () AS total_count');

  // Join keys are bound AFTER the select list has claimed its parameters, and
  // that is fine: positional parameters are numbered, not ordered, in the text.
  const joinSql = joins
    .map(({ kind, key, alias }) =>
      kind === 'event_prop'
        ? ` LEFT JOIN ${t.eventData} ${alias} ON ${alias}.website_id = e.website_id ` +
          `AND ${alias}.website_event_id = e.event_id AND ${alias}.data_key = ${p.add(key)}`
        : ` LEFT JOIN ${t.sessionData} ${alias} ON ${alias}.website_id = ${ctx.sessionLink}.website_id ` +
          `AND ${alias}.session_id = ${ctx.sessionLink}.session_id AND ${alias}.data_key = ${p.add(key)}`,
    )
    .join('');

  const ordinals = spec.groups.map((_, i) => i + 1);
  const outputName = name => {
    const g = spec.groups.findIndex(x => x.name === name);
    return g >= 0 ? `g${g}` : `m${spec.measures.findIndex(x => x.as === name)}`;
  };
  const orderBy = [
    ...(spec.order || []).map(o => `${outputName(o.field)}${o.desc ? ' DESC' : ''}`),
    // The groups themselves break ties, so equal sort values page stably.
    ...ordinals,
  ];
  // A function, so its LIMIT/OFFSET parameters are bound after the FROM and
  // WHERE that precede it in the text.
  const tail = () =>
    (ordinals.length ? ` GROUP BY ${ordinals.join(', ')}` : '') +
    (orderBy.length ? ` ORDER BY ${orderBy.join(', ')}` : '') +
    ` LIMIT ${p.add(spec.limit + 1)}` +
    (spec.offset ? ` OFFSET ${p.add(spec.offset)}` : '');
  return { selects, joinSql, tail };
}

export function buildAggregateSql(spec, site, t) {
  return spec.scope === 'sessions'
    ? buildSessionAggregateSql(spec, site, t)
    : buildEventAggregateSql(spec, site, t);
}

function buildEventAggregateSql(spec, site, t) {
  const p = new Params();
  const bySessionStart = spec.bucket.on === 'session_start';
  const needsSession =
    bySessionStart ||
    usesSession(spec.where) ||
    spec.groups.some(g => g.kind === 'session') ||
    spec.measures.some(m => usesSession(m.where));
  const { selects, joinSql, tail } = aggregateParts(spec, p, t, {
    bucketColumn: bySessionStart ? 's.created_at' : 'e.created_at',
    sessionFields: 's',
    sessionLink: 'e',
    measureConds: w => whereSql(w, p, t),
    column: target => (target.type === 'time' ? 'e.created_at' : `e.${target.column}`),
    firstOrder: ['e.created_at', 'e.event_id'],
  });
  const from = baseSql(spec, site, p, t, { session: needsSession, joins: joinSql });
  return { text: `SELECT ${selects.join(', ')} ${from}${tail()}`, values: p.values };
}

/**
 * One row per session, computed in two steps:
 *   ss  the sessions in scope, with their fields
 *   x   each with its events inside the window looked up beside it: first and
 *       last time, count, and one count per event name the request mentions,
 *       worked into duration and first_at/last_at -- a session with no events
 *       in the window stays, at duration 0
 * Groups, measures and the duration / session_events filters then run over x.
 *
 * Each session's events are a LATERAL lookup on the (website_id, session_id,
 * created_at) index, not a join the planner chooses. Left to choose, it can
 * walk every event of the window in session-id order (random reads, since
 * events are stored by time), and with stale or missing statistics it can
 * re-run the whole event pass per session -- measured at 3.6s and at over 20s
 * where this takes 1.8s for 50,000 sessions / 2M events, and 0.1s for one
 * user's sessions. ss is MATERIALIZED so the lookups run once per session.
 */
function buildSessionAggregateSql(spec, site, t) {
  const p = new Params();
  const siteParam = p.add(site);
  const from = p.add(spec.window.from);
  const to = p.add(spec.window.to);

  // Every event name the request counts by, each with its own column.
  const countColumns = new Map();
  const countColumn = name => {
    if (!countColumns.has(name)) countColumns.set(name, `c${countColumns.size}`);
    return countColumns.get(name);
  };
  const noteNames = w => {
    for (const k of ['all', 'any', 'none'])
      for (const n of w.sessionEvents?.[k] || []) countColumn(n);
  };
  noteNames(spec.where);
  for (const m of spec.measures) {
    noteNames(m.where);
    if (m.target?.type === 'count') countColumn(m.target.name);
  }

  const selection =
    spec.window.on === 'session_start'
      ? `s.created_at >= ${from} AND s.created_at < ${to}`
      : `s.session_id IN (SELECT e.session_id FROM ${t.event} e WHERE e.website_id = ${siteParam}::uuid ` +
        `AND e.created_at >= ${from} AND e.created_at < ${to})`;
  const sessionWhere = [
    `s.website_id = ${siteParam}::uuid`,
    selection,
    ...sessionConds(spec.where, p, t, { fields: 's', link: 's' }),
  ];
  const nameCounts = [...countColumns].map(
    ([name, col]) => `, COUNT(*) FILTER (WHERE e.event_name = ${p.add(name)}) AS ${col}`,
  );
  const ctes =
    `WITH ss AS MATERIALIZED (SELECT s.session_id, s.website_id, s.created_at AS session_start, ` +
    `${SESSION_FILTER_FIELDS.map(f => `s.${f}`).join(', ')} FROM ${t.session} s ` +
    `WHERE ${sessionWhere.join(' AND ')}), ` +
    'x AS (SELECT ss.*, ' +
    'COALESCE(EXTRACT(EPOCH FROM (ev.last_event_at - ev.first_event_at)), 0) AS duration_seconds, ' +
    'COALESCE(ev.first_event_at, ss.session_start) AS first_at, ' +
    'COALESCE(ev.last_event_at, ss.session_start) AS last_at, ' +
    'ev.event_count' +
    [...countColumns.values()].map(c => `, ev.${c}`).join('') +
    ' FROM ss CROSS JOIN LATERAL (SELECT MIN(e.created_at) AS first_event_at, ' +
    `MAX(e.created_at) AS last_event_at, COUNT(*) AS event_count${nameCounts.join('')} ` +
    `FROM ${t.event} e WHERE e.website_id = ss.website_id AND e.session_id = ss.session_id ` +
    `AND e.created_at >= ${from} AND e.created_at < ${to}) ev)`;

  const { selects, joinSql, tail } = aggregateParts(spec, p, t, {
    bucketColumn: 'x.session_start',
    sessionFields: 'x',
    sessionLink: 'x',
    measureConds: w => [
      ...sessionConds(w, p, t, { fields: 'x', link: 'x' }),
      ...sessionMetricConds(w, p, countColumn),
    ],
    column: target =>
      target.type === 'count' ? `x.${countColumn(target.name)}` : `x.${target.column}`,
    firstOrder: ['x.first_at', 'x.session_id'],
  });
  const outerWhere = sessionMetricConds(spec.where, p, countColumn);
  const where = outerWhere.length ? ` WHERE ${outerWhere.join(' AND ')}` : '';
  return {
    text: `${ctes} SELECT ${selects.join(', ')} FROM x${joinSql}${where}${tail()}`,
    values: p.values,
  };
}

/** Turn aggregate rows into the response shape, named by the caller's names. */
export function shapeAggregate(spec, rows) {
  const columns = [...spec.groups.map(g => g.name), ...spec.measures.map(m => m.as)];
  const truncated = rows.length > spec.limit;
  const cutValues = new Set();
  const out = rows.slice(0, spec.limit).map(row => {
    const shaped = {};
    spec.groups.forEach((g, i) => {
      shaped[g.name] = row[`g${i}`] ?? null;
    });
    spec.measures.forEach((m, i) => {
      const v = row[`m${i}`];
      if (m.kind === 'list') {
        shaped[m.as] = v ?? [];
        if (Number(row[`m${i}n`]) > m.limit) cutValues.add(m.as);
      } else if (v === null || v === undefined) shaped[m.as] = null;
      else if (m.kind === 'value') shaped[m.as] = v;
      else if (v instanceof Date) shaped[m.as] = v.toISOString();
      else shaped[m.as] = Number(v);
    });
    return shaped;
  });
  const result = { columns, rows: out, truncated };
  if (cutValues.size) result.values_truncated = [...cutValues];
  if (spec.offset) result.offset = spec.offset;
  if (spec.includeTotal) result.total = rows.length ? Number(rows[0].total_count) : null;
  return result;
}

// --- events & sessions -------------------------------------------------------

const EVENT_COLUMNS =
  'e.event_id, e.session_id, e.visit_id, e.created_at, e.event_type, ' +
  'e.event_name, e.url_path, e.hostname, e.referrer_domain';

const dirSql = desc => (desc ? ' DESC' : '');

/**
 * One page of matching events, by time (oldest first unless asked otherwise),
 * then by id in the same direction so equal times never shuffle between pages.
 */
export function buildEventsSql(spec, site, t) {
  const p = new Params();
  const base = baseSql(spec, site, p, t);
  const offset = (spec.page.number - 1) * spec.page.size;
  const dir = dirSql(spec.order[0].desc);
  const total = spec.includeTotal ? ', COUNT(*) OVER () AS total_count' : '';
  return {
    text:
      `SELECT ${EVENT_COLUMNS}${total} ${base} ORDER BY e.created_at${dir}, e.event_id${dir} ` +
      `LIMIT ${p.add(spec.page.size + 1)} OFFSET ${p.add(offset)}`,
    values: p.values,
  };
}

/**
 * One page of sessions, with first_at / last_at / event_count over each
 * session's MATCHING events -- so they answer "how many record.exported in this
 * session", not "how long was it" (a sessions aggregate answers that).
 *
 * window.on "event": the sessions that have at least one matching event.
 * window.on "session_start": the sessions that started in the window and pass
 * the session filters, INCLUDING those with no events in it (first_at and
 * last_at null, event_count 0) -- unless the request filters events, in which
 * case a session needs at least one that matches.
 */
export function buildSessionsPageSql(spec, site, t) {
  const p = new Params();
  const order = spec.order[0];
  const dir = dirSql(order.desc);
  const total = spec.includeTotal ? ', COUNT(*) OVER () AS total_count' : '';

  if (spec.window.on === 'session_start') {
    const siteParam = p.add(site);
    const from = p.add(spec.window.from);
    const to = p.add(spec.window.to);
    const eventWhere = [
      'e.website_id = s.website_id',
      'e.session_id = s.session_id',
      `e.created_at >= ${from}`,
      `e.created_at < ${to}`,
      ...eventConds(spec.where, p, t),
    ];
    const where = [
      `s.website_id = ${siteParam}::uuid`,
      `s.created_at >= ${from}`,
      `s.created_at < ${to}`,
      ...sessionConds(spec.where, p, t, { fields: 's', link: 's' }),
      ...(hasEventFilters(spec.where) ? ['m.event_count > 0'] : []),
    ];
    const key = {
      first_at: 'm.first_at',
      last_at: 'm.last_at',
      created_at: 's.created_at',
      event_count: 'm.event_count',
    }[order.field];
    return {
      text:
        'SELECT s.session_id, m.first_at, m.last_at, m.event_count' +
        `${total} FROM ${t.session} s CROSS JOIN LATERAL (SELECT MIN(e.created_at) AS first_at, ` +
        `MAX(e.created_at) AS last_at, COUNT(*) AS event_count FROM ${t.event} e ` +
        `WHERE ${eventWhere.join(' AND ')}) m WHERE ${where.join(' AND ')} ` +
        `ORDER BY ${key}${dir}, s.session_id${dir} LIMIT ${p.add(spec.page.size + 1)} ` +
        `OFFSET ${p.add((spec.page.number - 1) * spec.page.size)}`,
      values: p.values,
    };
  }

  const byStart = order.field === 'created_at';
  const base = baseSql(spec, site, p, t, { session: byStart });
  const key = {
    first_at: 'MIN(e.created_at)',
    last_at: 'MAX(e.created_at)',
    created_at: 's.created_at',
    event_count: 'COUNT(*)',
  }[order.field];
  return {
    text:
      'SELECT e.session_id, MIN(e.created_at) AS first_at, ' +
      `MAX(e.created_at) AS last_at, COUNT(*) AS event_count${total} ${base} ` +
      `GROUP BY e.session_id${byStart ? ', s.created_at' : ''} ` +
      `ORDER BY ${key}${dir}, e.session_id${dir} LIMIT ${p.add(spec.page.size + 1)} ` +
      `OFFSET ${p.add((spec.page.number - 1) * spec.page.size)}`,
    values: p.values,
  };
}

/** The session rows themselves, for the ids on one page. */
export function buildSessionRowsSql(site, ids, t) {
  return {
    text:
      'SELECT session_id, created_at, browser, os, device, screen, language, country, region, city ' +
      `FROM ${t.session} WHERE website_id = $1::uuid AND session_id = ANY($2::uuid[])`,
    values: [site, ids],
  };
}

/**
 * The matching events of the sessions on one page, at most `cap + 1` per
 * session so the handler can say which sessions it cut short.
 */
export function buildNestedEventsSql(spec, site, ids, cap, t) {
  const p = new Params();
  const base = baseSql(spec, site, p, t, { extra: [`e.session_id = ANY(${p.add(ids)}::uuid[])`] });
  return {
    text:
      `SELECT * FROM (SELECT ${EVENT_COLUMNS}, ` +
      'row_number() OVER (PARTITION BY e.session_id ORDER BY e.created_at, e.event_id) AS rn ' +
      `${base}) x WHERE rn <= ${p.add(cap + 1)} ORDER BY session_id, created_at, event_id`,
    values: p.values,
  };
}

/** Properties for a set of events (`event_data`) or sessions (`session_data`). */
export function buildPropsSql(kind, site, ids, selection, t) {
  const [table, idColumn] =
    kind === 'event' ? [t.eventData, 'website_event_id'] : [t.sessionData, 'session_id'];
  const values = [site, ids];
  let keyFilter = '';
  if (selection.keys) {
    values.push(selection.keys);
    keyFilter = ' AND data_key = ANY($3::text[])';
  }
  return {
    text:
      `SELECT ${idColumn} AS owner_id, data_key, string_value, number_value, date_value, data_type ` +
      `FROM ${table} WHERE website_id = $1::uuid AND ${idColumn} = ANY($2::uuid[])${keyFilter}`,
    values,
  };
}

/** One stored property value, decoded by the type Umami recorded for it. */
export function decodeProp(row) {
  switch (row.data_type) {
    case 2:
      return row.number_value === null ? null : Number(row.number_value);
    case 3:
      return row.string_value === 'true';
    case 4:
      return row.date_value ? new Date(row.date_value).toISOString() : row.string_value;
    case 5:
      try {
        return JSON.parse(row.string_value);
      } catch {
        return row.string_value;
      }
    default:
      return row.string_value;
  }
}

/** Group property rows by the event or session they belong to. */
export function propsByOwner(rows) {
  const out = new Map();
  for (const row of rows) {
    if (!out.has(row.owner_id)) out.set(row.owner_id, {});
    out.get(row.owner_id)[row.data_key] = decodeProp(row);
  }
  return out;
}

const iso = v => (v instanceof Date ? v.toISOString() : (v ?? null));

/** One event row in the response, with only the fields the caller selected. */
export function shapeEvent(row, fields, props) {
  const all = {
    id: row.event_id,
    session_id: row.session_id,
    visit_id: row.visit_id,
    created_at: iso(row.created_at),
    type: EVENT_TYPE_NAMES[row.event_type] || String(row.event_type),
    name: row.event_name ?? null,
    url_path: row.url_path ?? null,
    hostname: row.hostname ?? null,
    referrer_domain: row.referrer_domain ?? null,
  };
  const out = Object.fromEntries(fields.map(f => [f, all[f]]));
  if (props) out.props = props;
  return out;
}

export function shapeSession(row, page, fields) {
  const all = {
    id: row.session_id,
    created_at: iso(row.created_at),
    browser: row.browser ?? null,
    os: row.os ?? null,
    device: row.device ?? null,
    screen: row.screen ?? null,
    language: row.language ?? null,
    country: row.country ?? null,
    region: row.region ?? null,
    city: row.city ?? null,
  };
  return {
    // The id is the row's identity, so it is always present -- `session_fields`
    // chooses the descriptive fields around it.
    id: all.id,
    ...Object.fromEntries(fields.map(f => [f, all[f]])),
    first_at: iso(page.first_at),
    last_at: iso(page.last_at),
    event_count: Number(page.event_count),
  };
}

// --- schema ------------------------------------------------------------------

/**
 * What a site holds in a window: named events with their property keys, and
 * every event and session property key with its stored type. Each list is
 * capped at `cap` entries and fetched one over, so the handler can say when a
 * list was cut short.
 */
export function buildSchemaSql(site, window, cap, t) {
  const v = [site, window.from, window.to, cap + 1];
  const inWindow = a =>
    `${a}.website_id = $1::uuid AND ${a}.created_at >= $2 AND ${a}.created_at < $3`;
  return {
    events: {
      text:
        `SELECT e.event_name AS name, COUNT(*) AS count, MAX(e.created_at) AS last_at FROM ${t.event} e ` +
        `WHERE ${inWindow('e')} AND e.event_name IS NOT NULL GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT $4`,
      values: v,
    },
    eventKeys: {
      text:
        `SELECT e.event_name AS name, d.data_key AS key FROM ${t.eventData} d ` +
        `JOIN ${t.event} e ON e.event_id = d.website_event_id AND e.website_id = d.website_id ` +
        `WHERE ${inWindow('d')} AND e.event_name IS NOT NULL GROUP BY 1, 2 ORDER BY 1, 2`,
      values: v.slice(0, 3),
    },
    eventProps: {
      text:
        `SELECT d.data_key AS key, d.data_type AS type FROM ${t.eventData} d ` +
        `WHERE ${inWindow('d')} GROUP BY 1, 2 ORDER BY 1, 2 LIMIT $4`,
      values: v,
    },
    sessionProps: {
      text:
        `SELECT d.data_key AS key, d.data_type AS type FROM ${t.sessionData} d ` +
        `WHERE ${inWindow('d')} GROUP BY 1, 2 ORDER BY 1, 2 LIMIT $4`,
      values: v,
    },
  };
}
