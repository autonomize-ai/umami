/**
 * Read-only access to Umami's Postgres, for the query API.
 *
 * WHY THE BRIDGE TALKS TO THE DATABASE AT ALL
 *
 * Everything else here goes through Umami's REST API with the staff token. That
 * API answers fixed reports; it cannot list one site's raw events with their
 * properties, or group by an arbitrary property key. The query API needs both,
 * so it reads the tables directly -- and only reads.
 *
 * HOW "ONLY READS" IS ENFORCED, WITHOUT A SECOND DATABASE ROLE
 *
 * The connection reuses Umami's own DATABASE_URL, so a deployment needs no new
 * role, secret or DBA step. What keeps it read-only is that every query runs
 * inside `BEGIN ... READ ONLY` and is always rolled back: Postgres itself refuses
 * any write in that transaction (SQLSTATE 25006), whatever role it runs as.
 *
 * No caller-written SQL reaches this connection in the first place: the
 * statements come from query.mjs, where every identifier is from a fixed list
 * and every caller value is a bind parameter. The guard does not rely on that
 * alone, though. The handle which a query function receives (reader() below) runs
 * one SELECT per call over the extended protocol, and the transaction has
 * taken its snapshot before that handle exists, so neither `COMMIT; ...` nor
 * `SET TRANSACTION READ WRITE` can switch the read-only mode off -- each was
 * tried against Postgres 16 and refused.
 *
 * Where a deployment wants the database to enforce it as well, it can point
 * BRIDGE_QUERY_DATABASE_URL at a role that holds SELECT and nothing else; the
 * chart exposes that as bridge.query.database.existingSecret. The transaction
 * guard stays on either way.
 *
 * WHY pg IS IMPORTED LAZILY
 *
 * The bridge's first job is the dashboard sign-in and app provisioning. If the
 * driver or the database is unavailable, those must keep working: the query
 * endpoints answer 503, and nothing else notices.
 */

const MANAGED_IDENTITY = process.env.AZURE_USE_MANAGED_IDENTITY === "true";
const AZURE_POSTGRES_SCOPE =
  "https://ossrdbms-aad.database.windows.net/.default";

let poolPromise = null;

/** The connection string the query API uses, and the schema Umami's tables live in. */
export function queryDatabaseConfig(env = process.env) {
  const url = env.BRIDGE_QUERY_DATABASE_URL || env.DATABASE_URL || "";
  if (!url) return null;
  let schema = "public";
  try {
    // Umami's DATABASE_URL carries its schema as a Prisma-style `?schema=`.
    schema = new URL(url).searchParams.get("schema") || "public";
  } catch {
    return null;
  }
  return { url, schema };
}

async function createPool({ url }, { max, log }) {
  const { default: pg } = await import("pg");

  let options;
  if (MANAGED_IDENTITY) {
    // Mirrors createAzurePool in src/lib/azure-db.ts: a fresh Entra token per
    // connection, because a token in a connection string would expire under a
    // long-lived pool. The password in the URL, if any, is ignored.
    const { DefaultAzureCredential } = await import("@azure/identity");
    const credential = new DefaultAzureCredential();
    const parsed = new URL(url);
    const sslmode = parsed.searchParams.get("sslmode");
    options = {
      host: parsed.hostname,
      port: parsed.port ? Number(parsed.port) : 5432,
      user: decodeURIComponent(parsed.username),
      database: parsed.pathname.replace(/^\//, "") || undefined,
      ssl: sslmode === "disable" ? false : { rejectUnauthorized: true },
      password: async () => {
        const token = await credential.getToken(AZURE_POSTGRES_SCOPE);
        if (!token?.token)
          throw new Error("No Microsoft Entra access token for PostgreSQL.");
        return token.token;
      },
    };
  } else {
    // The same connection-string path Umami's own runtime client uses
    // (src/lib/prisma.ts), so TLS and the `schema` parameter behave the same.
    options = { connectionString: url };
  }

  const pool = new pg.Pool({
    ...options,
    max,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
    application_name: "umami-bridge-query",
  });
  // An idle client that errors (a database restart, say) must not become an
  // unhandled 'error' event, which would take down the whole sidecar.
  pool.on("error", (err) =>
    log("query pool: idle client error --", err.message),
  );
  return pool;
}

/**
 * The only handle a query function gets: one statement per call, always over
 * the extended protocol. node-postgres otherwise falls back to the SIMPLE
 * protocol when a query has no bind values, and the simple protocol runs every
 * statement in the string -- so `COMMIT; DELETE ...` would end the read-only
 * transaction and write. Verified against Postgres 16: forced extended mode
 * refuses that string outright (42601, multiple commands).
 *
 * And only SELECT (or WITH ... SELECT): a lone `COMMIT` is one statement, and
 * would end the read-only transaction so that the NEXT call autocommits. A
 * data-modifying CTE still starts with WITH, and the read-only transaction
 * refuses it (25006).
 */
const READ_STATEMENT = /^\s*(SELECT|WITH)\b/i;

function reader(client) {
  return {
    query: (text, values = []) => {
      if (!READ_STATEMENT.test(text)) {
        return Promise.reject(
          new Error("The query reader runs SELECT statements only."),
        );
      }
      return client.query({ text, values, queryMode: "extended" });
    },
  };
}

/**
 * Run `fn(reader)` inside a read-only transaction with a statement timeout,
 * then roll back. Rejects with { status: 503 } when the database is not
 * configured or cannot be reached.
 */
export async function withReadOnly(config, fn, { timeoutMs, poolMax, log }) {
  if (!config) {
    throw Object.assign(
      new Error("The query API has no database configured."),
      { status: 503 },
    );
  }
  if (!poolPromise) {
    poolPromise = createPool(config, { max: poolMax, log }).catch((err) => {
      // Retried on the next request rather than cached: a driver that failed to
      // load stays failed, but a database that was briefly down should not.
      poolPromise = null;
      throw err;
    });
  }

  let client;
  try {
    client = await (await poolPromise).connect();
  } catch (err) {
    log("query: could not connect --", err.message);
    throw Object.assign(new Error("The analytics database is unavailable."), {
      status: 503,
    });
  }

  // pg-pool removes its own error listener from a client while it is checked
  // out, and pg emits 'error' on the client when the connection drops -- even
  // mid-query, where the query's promise also rejects. With no listener, Node
  // treats that event as an uncaught exception and the whole sidecar exits on a
  // database restart or failover. This listener keeps it to the one request,
  // and marks the client so it is discarded rather than returned to the pool.
  let broken = false;
  const onError = (err) => {
    broken = true;
    log("query: connection lost --", err.message);
  };
  client.on("error", onError);
  try {
    // REPEATABLE READ: every statement of one answer reads the same snapshot,
    // so a page, its properties and its total agree with each other while
    // events keep arriving. A read-only
    // transaction cannot hit a serialization failure, so this costs nothing.
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    // Not a bind parameter: SET does not take one. The value is an integer
    // from configuration, coerced here so nothing else can reach the text.
    await client.query(
      `SET LOCAL statement_timeout = ${Math.max(1, Math.trunc(timeoutMs))}`,
    );
    // Takes the transaction's snapshot. Until a query has run, Postgres still
    // accepts `SET TRANSACTION READ WRITE`; after this it refuses it (25001), so
    // the read-only mode cannot be switched off from inside.
    await client.query("SELECT 1");
    return await fn(reader(client));
  } finally {
    try {
      await client.query("ROLLBACK");
    } catch {
      broken = true;
    }
    // A client whose connection failed mid-query is discarded, not reused.
    client.off("error", onError);
    client.release(broken || undefined);
  }
}
