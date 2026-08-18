/* eslint-disable no-console */
import 'dotenv/config';
import { execSync } from 'node:child_process';
import { PrismaPg } from '@prisma/adapter-pg';
import chalk from 'chalk';
import { PrismaClient } from '../generated/prisma/client.js';
import { isAzureManagedIdentityEnabled, withAzureToken } from './azure-db.js';

const MIN_VERSION = '9.4.0';
const MIN_VERSION_NUM = 90400;

if (process.env.SKIP_DB_CHECK) {
  console.log('Skipping database check.');
  process.exit(0);
}

// This check is one-shot, so a single token covers it — unlike the long-lived
// runtime pool, which refreshes per connection.
const url = new URL(
  isAzureManagedIdentityEnabled()
    ? await withAzureToken(process.env.DATABASE_URL)
    : process.env.DATABASE_URL,
);

const adapter = new PrismaPg(
  { connectionString: url.toString() },
  { schema: url.searchParams.get('schema') },
);

const prisma = new PrismaClient({ adapter });

function success(msg) {
  console.log(chalk.greenBright(`✓ ${msg}`));
}

function error(msg) {
  console.log(chalk.redBright(`✗ ${msg}`));
}

async function checkEnv() {
  if (!process.env.DATABASE_URL) {
    throw new Error('DATABASE_URL is not defined.');
  } else {
    success('DATABASE_URL is defined.');
  }

  if (process.env.REDIS_URL) {
    success('REDIS_URL is defined.');
  }
}

async function checkConnection() {
  try {
    await prisma.$connect();

    success('Database connection successful.');
  } catch (e) {
    throw new Error(`Unable to connect to the database: ${e.message}`);
  }
}

async function checkDatabaseVersion() {
  const query = await prisma.$queryRaw`select current_setting('server_version_num') as version_num`;
  const version = Number(query[0]?.version_num);

  if (!Number.isFinite(version)) {
    throw new Error('Unable to determine database version.');
  }

  if (version < MIN_VERSION_NUM) {
    throw new Error(
      `Database version is not compatible. Please upgrade to ${MIN_VERSION} or greater.`,
    );
  }

  success('Database version check successful.');
}

async function applyMigration() {
  if (!process.env.SKIP_DB_MIGRATION) {
    const directUrl = process.env.DIRECT_DATABASE_URL || process.env.DATABASE_URL;

    // The Prisma CLI reads DATABASE_URL itself and cannot use our pool, so the
    // token is embedded in the URL it is handed. Migrations are short-lived.
    const migrationUrl = isAzureManagedIdentityEnabled()
      ? await withAzureToken(directUrl)
      : directUrl;

    console.log(
      execSync('prisma migrate deploy', {
        env: { ...process.env, DATABASE_URL: migrationUrl },
      }).toString(),
    );

    success('Database is up to date.');
  }
}

(async () => {
  let err = false;
  for (const fn of [checkEnv, checkConnection, checkDatabaseVersion, applyMigration]) {
    try {
      await fn();
    } catch (e) {
      error(e.message);
      err = true;
    } finally {
      if (err) {
        process.exit(1);
      }
    }
  }
})();
