# PARA OAuth handoff

Implementation candidate: 2026-10-05. Pilot status and remaining acceptance live
in [WatZappa's canonical queue](../../WatZappa/docs/QUARTER_PLAN_2026Q4.md).
The exchange tests seed completed OAuth sessions; they do not prove a live PDS
login or a deployed client.

## Deploy the broker before the new PARA client

1. Back up the broker database and apply migrations
   `040_oauth_exchange_binding.sql` and `041_oauth_code_binding_retention.sql`
   using the normal migration runner. They add
   optional challenge columns; retain them when rolling the application back.
2. Set `SERVICE_URL` to the broker's public HTTPS origin. Its
   `/oauth-client-metadata.json` and `/v1/sessions/oauth/callback` must be
   reachable by the actual PDS. Keep the existing production issuer/secret
   configuration; no demo break-glass setting is needed.
3. Enable `m8:auth:oauth_mobile_handoff` and disable
   `m8:auth:dev_token_bootstrap` in the effective GrowthBook configuration.
   The handoff flag defaults off in production. Its historical name now covers
   explicit web handoffs as well as native handoffs.
4. Set `OAUTH_RETURN_TO_ALLOWLIST` to exact callbacks, for example
   `im8://oauth/callback,para://m8-auth,https://<actual-PARA-origin>/m8-auth`.
   Replace the example origin. No wildcard, query, fragment or URL credentials
   are accepted. Web callbacks require HTTPS except loopback development.
   Keep the iM8 callback if that client is still supported.
5. Include the actual PARA web origin in `CORS_ORIGIN`, and set PARA's
   `EXPO_PUBLIC_M8_BROKER_URL` to the broker's HTTPS origin. The web host must
   serve its SPA on `/m8-auth`; PARA's bskyweb route now does so.

## Contract

PARA posts `/v1/sessions/start` with the active DID, `platform: mobile|web`,
`returnTo`, and `exchangeChallenge` (PKCE S256, base64url). With dev bootstrap
off, a valid start returns 202 with `tokens: null`, `session: null`, and an
attempt containing `attemptId`, `authUrl`, `returnTo`, `exchangeChallenge` and
`expiresAt`. PARA verifies those values before opening the browser.

A completed callback redirects only `attempt_id` and a short-lived,
single-use `exchange_code`. A known attempt's failure redirects only
`attempt_id` and a generic `error`. Incoming provider query parameters are
explicitly excluded. Unknown or expired state does not choose a redirect.
A requested DID must match the provider's authenticated DID.

PARA posts the code, `attemptId` and its private `verifier` to
`/v1/sessions/exchange`. Attempt/verifier mismatches do not consume the code.
The code retains its verifier binding if its OAuth audit row is later removed.
Migration 041 backfills outstanding bindings and invalidates orphan codes whose
binding cannot be recovered; those clients must reconnect.
The response includes `authenticated`, `attemptId`, `sessionId`, `session` and
a complete token bundle. Codes expire after two minutes; attempts after ten.
Legacy clients without a challenge retain their existing code-only exchange.
PARA requires the strengthened response and fails closed against an old broker.

Refresh returns a rotated refresh token as well as an access token. Concurrent
rotation has one winner. Authenticated `/v1/sessions/logout` accepts a refresh
token and revokes that credential's replacement chain within the authenticated
session, preserving other devices. Access JWTs remain valid until their
configured expiry; this endpoint is not immediate JWT revocation. Offline
logout clears the client but cannot confirm server revocation.

## Supported-client acceptance still required

### Read-only deployment preflight

From the broker repository, run with the actual broker environment/database:

```sh
pnpm login:preflight --web-origin https://ACTUAL_PARA_ORIGIN
# In the current broker Docker image:
node build/bin/para_login_preflight.js --web-origin https://ACTUAL_PARA_ORIGIN
```

The platform wrapper provides `make login-preflight WEB_ORIGIN=https://ACTUAL_PARA_ORIGIN`.
The command inspects effective handoff/bootstrap flags, exact native/web
callbacks, explicit CORS and recorded migrations plus actual binding columns.
It opens only an existing database read-only, and probes public health,
OAuth metadata, CORS OPTIONS and the web `/m8-auth` route. It does not initialize
the app, create sessions, issue credentials or apply migrations. Output omits
secrets and remote response bodies; failed checks return a nonzero exit code.

`--local` permits loopback HTTP, not a LAN hostname over HTTP. `--config-only`
omits endpoint probes and records that narrower scope. A passed check covers
this invocation's environment/database and the selected public responses;
it cannot attest a running process's flags/code revision or prove provider and
client behavior. Record deployment revisions separately. Run the command inside
the deployed broker container to avoid inspecting a different local database.

### Provider and device results

Exercise a real provider login with bootstrap off on iOS, Android and the
selected web host, including browser cancellation/back, expiry/replay, wrong
account, account switching, refresh and logout. Native release credentials use
SecureStore without a plaintext fallback. Web credentials stay in memory;
callback binding lives only in the originating tab's sessionStorage and is
removed after use. Web reload requires reconnecting. Persistent web sessions
need an explicit design/acceptance decision before being promised.

Record exact client/broker revisions, effective flags, callback allowlist,
domains and outcomes in the canonical execution record. The callback fixture
also emits the existing OAuth client's missing-lock warning: multi-worker
OAuth concurrency has not been accepted by these tests.
