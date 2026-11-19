# genesis-base-images flavor: node-22-dev, rebuilt nightly with the OS upgrade, package floors and Wiz
# (this replaces the node 22.23.5-alpine pin and the in-file openssl/zlib/curl upgrades). The runner
# needs a shell (scripts/start-docker.sh) and pnpm, so all stages use -dev rather than node-22-slim.
# Digest and tag are rewritten together by the genesis-base bump.
# genesis-base-bump: node-22-dev 20261119-r1
ARG NODE_IMAGE=sprintregistry.azurecr.io/genesis-base/node-22-dev@sha256:ee8e05b9ec68d64a2936ff83c87e81a188e2e36f57016d5567d248408b102b61
# 11.28.8 bundles undici 6.29.1 in dist/node_modules; 11.28.2 bundled 6.28.1
# (CVE-2026-109869 / GHSA-xjj6-f33q-929c, high), which image scanning reports
# against /usr/local/lib/node_modules/pnpm in the runner stage.
ARG PNPM_VERSION="11.28.8"
# Keep in sync with the prisma/@prisma/* versions in package.json
ARG PRISMA_VERSION="7.9.1"
# @azure/identity is installed into the runner stage for the startup scripts
# (scripts/azure-db.js), which run outside the Next.js bundle.
ARG AZURE_IDENTITY_VERSION="4.13.1"
# pg is installed into the runner stage for the login bridge's query API
# (bridge/db.mjs), which runs outside the Next.js bundle and so cannot rely on
# the bundle's traced copy. Keep in sync with "pg" in package.json.
ARG PG_VERSION="8.23.0"
# Keep in sync with the deepmerge-ts override in pnpm-workspace.yaml
ARG DEEPMERGE_TS_VERSION="^8.0.2"
# Keep in sync with the mysql2 override in pnpm-workspace.yaml
ARG MYSQL2_VERSION="^3.23.1"
# Keep in sync with the @azure/msal-node override in pnpm-workspace.yaml
ARG MSAL_NODE_VERSION=">=7.1.0 <8"

# Install dependencies only when needed
FROM ${NODE_IMAGE} AS deps
ARG PNPM_VERSION

USER root
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN npm install -g pnpm@${PNPM_VERSION}

# pnpm-workspace.yaml has to be copied, not written from scratch: pnpm 11 reads
# `overrides` only from that file (a package.json `pnpm.overrides` block is
# ignored), and --frozen-lockfile fails with ERR_PNPM_LOCKFILE_CONFIG_MISMATCH
# if the overrides it sees do not match the ones recorded in the lockfile.
# Append the build-only setting rather than overwriting the file.
RUN printf 'strictDepBuilds: false\n' >> pnpm-workspace.yaml

RUN pnpm install --frozen-lockfile

# Rebuild the source code only when needed
FROM ${NODE_IMAGE} AS builder
USER root
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
COPY docker/proxy.ts ./src

ARG BASE_PATH

ENV BASE_PATH=$BASE_PATH
ENV NEXT_TELEMETRY_DISABLED=1
ENV DATABASE_URL="postgresql://user:pass@localhost:5432/dummy"

RUN npm run build-docker

# Production image, copy all the files and run next
FROM ${NODE_IMAGE} AS runner
USER root
WORKDIR /app

ARG NODE_OPTIONS
ARG PNPM_VERSION
ARG PRISMA_VERSION
ARG AZURE_IDENTITY_VERSION
ARG PG_VERSION
ARG DEEPMERGE_TS_VERSION
ARG MYSQL2_VERSION
ARG MSAL_NODE_VERSION

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_OPTIONS=$NODE_OPTIONS

RUN addgroup -S -g 1001 nodejs
RUN adduser -S -u 1001 -G nodejs nextjs
# Bootstrap pnpm with the bundled npm, then remove npm in the same layer so the vulnerable
# packages vendored inside the npm CLI are not shipped in the final image. OS package CVEs
# (openssl, zlib, curl) are handled by the nightly genesis-base rebuild; curl and libc6-compat are
# not needed (glibc base, nothing here calls curl).
RUN set -x \
    && npm install -g pnpm@${PNPM_VERSION} \
    && rm -rf /usr/lib/node_modules/npm /usr/bin/npm /usr/bin/npx
RUN echo {} > package.json

# The overrides have to be repeated here. This stage resolves its own dependency
# tree from scratch, and prisma pulls @prisma/config -> deepmerge-ts 7.1.5 and
# mysql2 3.15.3, and @azure/identity pulls @azure/msal-node 5.x; the app
# lockfile does not constrain it. Without these the runtime install puts the
# vulnerable copies back into /app/node_modules - and writes them into the
# /app/pnpm-lock.yaml that `pnpm add` generates - so the image stays flagged
# even though the app lockfile is clean. Both of those are paths image scanning
# reports against.
RUN printf "allowBuilds:\n  '@prisma/engines': true\n  prisma: false\nverifyDepsBeforeRun: false\noverrides:\n  deepmerge-ts: '${DEEPMERGE_TS_VERSION}'\n  mysql2: '${MYSQL2_VERSION}'\n  '@azure/msal-node': '${MSAL_NODE_VERSION}'\n" > pnpm-workspace.yaml

# Script dependencies
RUN pnpm add npm-run-all dotenv chalk semver \
    @azure/identity@${AZURE_IDENTITY_VERSION} \
    pg@${PG_VERSION} \
    prisma@${PRISMA_VERSION} \
    @prisma/client@${PRISMA_VERSION} \
    @prisma/adapter-pg@${PRISMA_VERSION}

# Assert the @prisma/engines postinstall actually downloaded the engine
# binaries. If pnpm blocked the build script (e.g. allowBuilds not honored by
# the installed pnpm version), prisma would try to download engines at runtime
# as the non-root user and fail with a permissions error.
RUN ls node_modules/.pnpm/@prisma+engines@${PRISMA_VERSION}/node_modules/@prisma/engines/*engine* \
    || (echo "ERROR: Prisma engine binaries missing - @prisma/engines postinstall was blocked" && exit 1)

COPY --from=builder --chown=nextjs:nodejs /app/public ./public
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/prisma.config.ts ./prisma.config.ts
COPY --from=builder /app/scripts ./scripts
COPY --from=builder /app/generated ./generated

# Automatically leverage output traces to reduce image size
# https://nextjs.org/docs/advanced-features/output-file-tracing
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

# Login bridge — a second entry point into the SAME image, run as a sidecar
# with `node bridge/server.mjs` instead of the default CMD. Deliberately not a
# separate image: it is ~200 lines of dependency-free Node, and a second image
# would mean a second build, a second tag to keep in step with this one, and a
# second thing for image scanning to clear.
COPY --chown=nextjs:nodejs bridge ./bridge

USER nextjs

EXPOSE 3000

ENV HOSTNAME=0.0.0.0
ENV PORT=3000

# The Chainguard node image sets ENTRYPOINT /usr/bin/node, which would receive this CMD as arguments.
ENTRYPOINT []
CMD ["sh", "scripts/start-docker.sh"]
