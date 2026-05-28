# mubEZ

mubEZ is the backend for the iM8 app. It provides the proof broker, credential wallet, scoped grant, trust policy, civic identity, community governance, and verification APIs used by the frontend.

The service is built with AdonisJS, TypeScript, SQLite, AT Protocol integrations, and zero-knowledge proof helpers for privacy-preserving identity flows.

## What is in this repo

- HTTP API controllers and middleware under `app/`.
- Service logic, database migrations, identity wallet, AT Protocol helpers, and trust-policy code under `src/`.
- Community lexicons under `lexicons/app/m8/community/`.
- ZKP circuits and verifier artifacts under `zkp/`.
- Integration, unit, and e2e tests under `tests/`.
- Docker and Compose files for local service runs.

The iM8 Expo frontend is intentionally not included here. It lives in the separate `iM8` repository.

## Requirements

- Node.js 22 or newer.
- pnpm 8.15.9 through Corepack.

## Setup

```bash
corepack enable
corepack prepare pnpm@8.15.9 --activate
pnpm install --frozen-lockfile
cp .env.example .env
pnpm db:migrate
```

Before using production-like flows, replace every placeholder secret in `.env`, especially `JWT_SECRET`, `APP_KEY`, `COOKIE_SECRET`, and issuer key material.

## Development

```bash
pnpm dev
```

The API defaults to `http://localhost:8787`. Health is available at:

```bash
curl http://localhost:8787/v1/health
```

## Quality Checks

```bash
pnpm lint
pnpm build
pnpm test:integration
pnpm test:e2e
```

## Docker

```bash
docker compose up --build
```

The container stores local SQLite data in the `mubez-data` Docker volume.

## Repository Boundary

Do not commit local databases, `.env` files, build output, generated proving keys, generated Adonis artifacts, or frontend app code.
