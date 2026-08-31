ARG NODE_IMAGE_VERSION="22-alpine"
ARG PNPM_VERSION="11.21.0"
# Keep in sync with the prisma/@prisma/* versions in package.json
ARG PRISMA_VERSION="7.9.1"
# @azure/identity is installed into the runner stage for the startup scripts
# (scripts/azure-db.js), which run outside the Next.js bundle.
ARG AZURE_IDENTITY_VERSION="4.13.1"
# Keep in sync with the deepmerge-ts override in pnpm-workspace.yaml
ARG DEEPMERGE_TS_VERSION="^8.0.2"

# Install dependencies only when needed
FROM node:${NODE_IMAGE_VERSION} AS deps
ARG PNPM_VERSION

# Check https://github.com/nodejs/docker-node/tree/b4117f9333da4138b03a546ec926ef50a31506c3#nodealpine to understand why libc6-compat might be needed.
RUN apk add --no-cache libc6-compat
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
FROM node:${NODE_IMAGE_VERSION} AS builder
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
FROM node:${NODE_IMAGE_VERSION} AS runner
WORKDIR /app

ARG NODE_OPTIONS
ARG PNPM_VERSION
ARG PRISMA_VERSION
ARG AZURE_IDENTITY_VERSION
ARG DEEPMERGE_TS_VERSION

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_OPTIONS=$NODE_OPTIONS

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs
# Upgrade the OpenSSL runtime ahead of the base image. node:22-alpine (Alpine
# 3.24.1) still ships libssl3/libcrypto3 3.5.7-r0, while Alpine v3.24/main
# already carries the patched 3.5.8-r0 - so the fix is reachable without moving
# off the tag, and arrives on its own once the base image is rebuilt. Image
# scanning blocks on seven HIGH CVEs against 3.5.7-r0: CVE-2026-14456,
# CVE-2026-14457, CVE-2026-18798, CVE-2026-54874, CVE-2026-63072,
# CVE-2026-63075 and CVE-2026-63076. This is the only stage that ships, so it is
# the only stage that needs the upgrade, and it has to precede the curl install
# so libcurl resolves against the patched libssl3.
#
# Then bootstrap pnpm with the bundled npm and remove npm in the same layer, so
# the vulnerable packages vendored inside the npm CLI are not shipped in the
# final image. pnpm is the only package manager needed at build and runtime.
RUN set -x \
    && apk upgrade --no-cache libssl3 libcrypto3 \
    && apk add --no-cache curl libc6-compat \
    && npm install -g pnpm@${PNPM_VERSION} \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

RUN echo {} > package.json

# The override has to be repeated here. This stage resolves its own dependency
# tree from scratch, and prisma pulls @prisma/config -> deepmerge-ts 7.1.5; the
# app lockfile does not constrain it. Without this the runtime install puts the
# vulnerable copy back into /app/node_modules and the image stays flagged.
RUN printf "allowBuilds:\n  '@prisma/engines': true\n  prisma: false\nverifyDepsBeforeRun: false\noverrides:\n  deepmerge-ts: '${DEEPMERGE_TS_VERSION}'\n" > pnpm-workspace.yaml

# Script dependencies
RUN pnpm add npm-run-all dotenv chalk semver \
    @azure/identity@${AZURE_IDENTITY_VERSION} \
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

USER nextjs

EXPOSE 3000

ENV HOSTNAME=0.0.0.0
ENV PORT=3000

CMD ["sh", "scripts/start-docker.sh"]
