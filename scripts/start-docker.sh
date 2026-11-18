#!/bin/sh
# Container startup: the one-shot DB check/migration and tracker update, then exec the server as PID 1 (no idle npm
# parents holding memory); the TLS entry runs `node server.js` unless GENESIS_TLS_CERT/KEY are set.
# PATH gains node_modules/.bin so `prisma migrate deploy` resolves the way `npm run` would.
set -e
export PATH="$PWD/node_modules/.bin:$PATH"

node scripts/check-db.js
node scripts/update-tracker.js
exec node scripts/tls-server.cjs
