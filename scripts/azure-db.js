import { DefaultAzureCredential } from '@azure/identity';

/**
 * Microsoft Entra (Azure AD) authentication helpers for the startup scripts.
 *
 * Mirrors src/lib/azure-db.ts, but the scripts run as plain ESM outside the
 * Next build, so they cannot import the TypeScript module.
 *
 * The runtime client uses a connection pool that mints a token per connection.
 * The Prisma CLI cannot: `prisma migrate deploy` reads DATABASE_URL directly,
 * so the token has to be embedded in the URL. Migrations are short-lived, so a
 * single token is enough for the run.
 */

const AZURE_POSTGRES_SCOPE = 'https://ossrdbms-aad.database.windows.net/.default';

let credential;

export function isAzureManagedIdentityEnabled() {
  return process.env.AZURE_USE_MANAGED_IDENTITY === 'true';
}

export async function getAzureAccessToken() {
  credential ??= new DefaultAzureCredential();

  const token = await credential.getToken(AZURE_POSTGRES_SCOPE);

  if (!token?.token) {
    throw new Error('Unable to acquire a Microsoft Entra access token for PostgreSQL.');
  }

  return token.token;
}

/**
 * Return the connection string with a freshly acquired access token as the
 * password. Any password already present is replaced.
 */
export async function withAzureToken(connectionString) {
  const url = new URL(connectionString);

  url.password = await getAzureAccessToken();

  return url.toString();
}
