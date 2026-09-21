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
RUN apk add --no-cache python3 make g++ && npm install -g pnpm@11.11.0
# pnpm-workspace.yaml carries the allowBuilds approvals — without it pnpm 11
# refuses to run the dependency build scripts (exit 1 on --frozen-lockfile).
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --prod --frozen-lockfile && pnpm store prune
COPY --from=builder /app/build ./build
RUN mkdir -p /app/data && chown -R node:node /app/data
USER node
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8787/v1/health || exit 1
CMD ["node", "--enable-source-maps", "build/bin/server.js"]
