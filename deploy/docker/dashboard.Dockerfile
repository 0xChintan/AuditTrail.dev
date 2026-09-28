# syntax=docker/dockerfile:1
# AuditTrail dashboard (Next.js standalone server).
#   docker build -f deploy/docker/dashboard.Dockerfile -t audittrail/dashboard .

# The build emits platform-independent JS, so it runs natively on the build host.
FROM --platform=$BUILDPLATFORM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS build
WORKDIR /src
RUN corepack enable
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json tsconfig.base.json ./
# Every workspace manifest, so the frozen lockfile matches.
COPY packages/core/package.json packages/core/
COPY packages/sdk/package.json packages/sdk/
COPY packages/mcp-sidecar/package.json packages/mcp-sidecar/
COPY apps/dashboard/package.json apps/dashboard/
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile --filter @audittrail/dashboard... --filter @audittrail/core
COPY packages/core packages/core
COPY apps/dashboard apps/dashboard
RUN pnpm --filter @audittrail/core build \
 && NEXT_OUTPUT=standalone NEXT_TELEMETRY_DISABLED=1 pnpm --filter @audittrail/dashboard build \
 && cd apps/dashboard \
 && cp -r public .next/standalone/apps/dashboard/ \
 && mkdir -p .next/standalone/apps/dashboard/.next \
 && cp -r .next/static .next/standalone/apps/dashboard/.next/

FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
WORKDIR /app
COPY --from=build --chown=node:node /src/apps/dashboard/.next/standalone ./
COPY --chmod=0755 deploy/docker/dashboard-entrypoint.sh /usr/local/bin/dashboard-entrypoint
USER node
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD wget -q -O /dev/null http://127.0.0.1:3000/verify || exit 1
ENTRYPOINT ["/usr/local/bin/dashboard-entrypoint"]
CMD ["node", "apps/dashboard/server.js"]
