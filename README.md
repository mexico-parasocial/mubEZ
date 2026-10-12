# mubEZ

mubEZ is the backend for the iM8 app. It provides the proof broker, credential wallet, scoped grant, trust policy, civic identity, community governance, and verification APIs used by the frontend.

The service is built with AdonisJS, TypeScript, SQLite, AT Protocol integrations, and zero-knowledge age proofs at INE enrollment. Credential presentations to verifiers are not zero-knowledge and not anonymous: they carry the account DID and the whole credential (see `docs/WALLET_PRIVACY.md`).

## What is in this repo

- HTTP API controllers and middleware under `app/`.
- Service logic, database migrations, identity wallet, AT Protocol helpers, and trust-policy code under `src/`.
- Community lexicons under `lexicons/app/m8/community/`.
- ZKP circuits and verifier artifacts under `zkp/`.
- Integration, unit, and e2e tests under `tests/`.
- Docker and Compose files for local service runs.

The iM8 Expo frontend is intentionally not included here. It lives in the separate `iM8` repository.

## Requirements

- Node.js 24.18 or newer.
- pnpm 11.11.0 through Corepack.

## Setup

```bash
corepack enable
corepack prepare pnpm@11.11.0 --activate
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

The production image (published to `ghcr.io/mexico-parasocial/mubez` by
`.github/workflows/image.yml`) adds two things, both off unless configured:

- **Secrets as files.** `NAME_FILE=/run/secrets/...` becomes `NAME` before the
  server starts (`docker/env-from-files.sh`). It refuses to start if both are
  set or the file is empty.
- **The bucket as the source of truth.** With `LITESTREAM_BUCKET` set
  (`LITESTREAM_PATH`, `LITESTREAM_ENDPOINT`, `LITESTREAM_REGION`,
  `LITESTREAM_FORCE_PATH_STYLE`, credentials in
  `LITESTREAM_ACCESS_KEY_ID[_FILE]`/`LITESTREAM_SECRET_ACCESS_KEY[_FILE]`),
  Litestream streams every change of the database to S3 within
  `LITESTREAM_SYNC_INTERVAL` (default 1 s), and a container that starts with
  no database restores it from there (`docker/entrypoint.sh`). The disk is
  then only a cache. Never run two brokers against the same bucket path.

para-platform runs it this way (`overrides/identity.yaml` there).

## Repository Boundary

Do not commit local databases, `.env` files, build output, generated proving keys, generated Adonis artifacts, or frontend app code.
