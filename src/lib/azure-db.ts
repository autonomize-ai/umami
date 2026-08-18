import { DefaultAzureCredential } from '@azure/identity';
import pg from 'pg';

/**
 * Microsoft Entra (Azure AD) authentication for Azure Database for PostgreSQL.
 *
 * Entra auth replaces the password with a short-lived access token (~1 hour).
 * A connection string cannot express that: it is read once, so every connection
 * opened after the token expires would fail to authenticate.
 *
 * node-postgres accepts `password` as a function and calls it for EVERY new
 * connection, and `@prisma/adapter-pg` accepts a `pg.Pool` instead of a
 * connection string. Combining the two lets the pool mint a fresh token
 * whenever it opens a connection, so expiry is handled without restarts.
 *
 * Opt in with AZURE_USE_MANAGED_IDENTITY=true. Unset, nothing here runs and the
 * stock connection-string path is used unchanged.
 */

const AZURE_POSTGRES_SCOPE = 'https://ossrdbms-aad.database.windows.net/.default';

let credential: DefaultAzureCredential | undefined;

export function isAzureManagedIdentityEnabled(): boolean {
  return process.env.AZURE_USE_MANAGED_IDENTITY === 'true';
}

export async function getAzureAccessToken(): Promise<string> {
  // DefaultAzureCredential resolves Workload Identity on AKS, and falls back to
  // EnvironmentCredential (AZURE_CLIENT_ID/SECRET/TENANT_ID) elsewhere — which
  // is how this can be exercised outside a federated-identity cluster.
  credential ??= new DefaultAzureCredential();

  const token = await credential.getToken(AZURE_POSTGRES_SCOPE);

  if (!token?.token) {
    throw new Error('Unable to acquire a Microsoft Entra access token for PostgreSQL.');
  }

  return token.token;
}

/**
 * Build a pool that authenticates with a freshly acquired token per connection.
 * The username must be the Entra principal mapped on the server (for example
 * via `pgaadauth_create_principal`), and any password in the URL is ignored.
 */
export function createAzurePool(connectionString: string): pg.Pool {
  const url = new URL(connectionString);
  const sslmode = url.searchParams.get('sslmode');

  return new pg.Pool({
    host: url.hostname,
    port: url.port ? Number(url.port) : 5432,
    user: decodeURIComponent(url.username),
    database: url.pathname.replace(/^\//, '') || undefined,
    // Azure requires TLS; `sslmode=disable` is honoured for local testing only.
    ssl: sslmode === 'disable' ? false : { rejectUnauthorized: true },
    password: () => getAzureAccessToken(),
  });
}
