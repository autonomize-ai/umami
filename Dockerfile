# genesis-base-images flavor: nightly OS upgrade, floors and Wiz. The runner needs a shell (start-docker.sh)
# and pnpm at build time, so all three stages use the -dev flavor rather than node-22-slim.
ARG NODE_IMAGE="sprintregistry.azurecr.io/genesis-base/node-22-dev:20261114-r1"
ARG PNPM_VERSION="11.21.0"
# Keep in sync with the prisma/@prisma/* versions in package.json
ARG PRISMA_VERSION="7.9.1"

# Install dependencies only when needed
FROM ${NODE_IMAGE} AS deps
ARG PNPM_VERSION

USER root
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN npm install -g pnpm@${PNPM_VERSION}

RUN printf 'strictDepBuilds: false\n' > pnpm-workspace.yaml

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

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_OPTIONS=$NODE_OPTIONS

RUN addgroup -S -g 1001 nodejs
RUN adduser -S -u 1001 -G nodejs nextjs
# Bootstrap pnpm with the bundled npm, then remove npm in the same layer so the
# vulnerable packages vendored inside the npm CLI are not shipped in the final
# image. pnpm is the only package manager needed at build and runtime.
RUN set -x \
    && npm install -g pnpm@${PNPM_VERSION} \
    && rm -rf /usr/lib/node_modules/npm /usr/bin/npm /usr/bin/npx

RUN echo {} > package.json

RUN printf "allowBuilds:\n  '@prisma/engines': true\n  prisma: false\nverifyDepsBeforeRun: false\n" > pnpm-workspace.yaml

# Script dependencies
RUN pnpm add npm-run-all dotenv chalk semver \
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

# The Chainguard node image sets ENTRYPOINT /usr/bin/node, which would receive this CMD as arguments.
ENTRYPOINT []
CMD ["sh", "scripts/start-docker.sh"]
