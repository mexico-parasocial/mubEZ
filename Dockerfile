# Static binary, copied into the runner (see docker/entrypoint.sh).
FROM litestream/litestream:0.3.13 AS litestream

FROM node:24.18-alpine3.23 AS builder
WORKDIR /app
RUN npm install -g pnpm@11.11.0
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.json ace.js adonisrc.ts ./
RUN pnpm install --frozen-lockfile
COPY app ./app
COPY bin ./bin
COPY config ./config
COPY start ./start
COPY src ./src
COPY zkp ./zkp
RUN pnpm build

FROM node:24.18-alpine3.23 AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8787
# python3/make/g++: better-sqlite3 compiles its native binding at install time
RUN apk add --no-cache python3 make g++ tini && npm install -g pnpm@11.11.0
# pnpm-workspace.yaml carries the allowBuilds approvals — without it pnpm 11
# refuses to run the dependency build scripts (exit 1 on --frozen-lockfile).
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --prod --frozen-lockfile && pnpm store prune
COPY --from=builder /app/build ./build
RUN mkdir -p /app/data && chown -R node:node /app/data
# Secrets as files (NAME_FILE=/run/secrets/...) and, when LITESTREAM_BUCKET is
# set, continuous replication of the database to the bucket.
COPY --from=litestream /usr/local/bin/litestream /usr/local/bin/litestream
COPY --chmod=755 docker/env-from-files.sh /usr/local/bin/env-from-files
COPY --chmod=755 docker/entrypoint.sh /usr/local/bin/mubez-entrypoint
COPY docker/litestream.yml /etc/litestream.yml
USER node
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8787/v1/health || exit 1
ENTRYPOINT ["/sbin/tini", "--", "env-from-files", "mubez-entrypoint"]
CMD ["node", "--enable-source-maps", "build/bin/server.js"]
