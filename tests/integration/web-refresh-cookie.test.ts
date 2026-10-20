import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'

process.env.DATABASE_PATH = join(mkdtempSync(join(tmpdir(), 'web-refresh-cookie-')), 'test.db')
process.env.GROWTHBOOK_FEATURE_OVERRIDES = JSON.stringify({
  'm8:auth:dev_token_bootstrap': false,
  'm8:auth:oauth_mobile_handoff': true,
})
process.env.OAUTH_RETURN_TO_ALLOWLIST = 'https://para.example/m8-auth'
process.env.CORS_ORIGIN = 'https://para.example'

const ORIGIN = 'https://para.example'
const cookieMode = { origin: ORIGIN, 'x-m8-refresh-transport': 'cookie' }

function refreshCookie(headers: Record<string, string>) {
  const header = headers['set-cookie'] ?? ''
  const match = header.match(/(?:^|,\s*)(m8_refresh=[^;]*)/)
  return { header, pair: match?.[1] ?? null }
}

describe('web refresh token cookie transport', () => {
  let app: TestApp
  let getDb: typeof import('../../src/db/connection.js').getDb
  let closeDb: typeof import('../../src/db/connection.js').closeDb
  let createAttempt: typeof import('../../src/services/oauthLoginAttempts.js').createOAuthLoginAttempt
  let completeAttempt: typeof import('../../src/services/oauthLoginAttempts.js').completeOAuthLoginAttempt
  let createCode: typeof import('../../src/services/oauthExchangeCodes.js').createExchangeCode
  before(async () => {
    const { buildApp } = await import('../../src/index.js')
    app = await buildApp()
    ;({ getDb, closeDb } = await import('../../src/db/connection.js'))
    ;({ createOAuthLoginAttempt: createAttempt, completeOAuthLoginAttempt: completeAttempt } =
      await import('../../src/services/oauthLoginAttempts.js'))
    ;({ createExchangeCode: createCode } = await import('../../src/services/oauthExchangeCodes.js'))
    getDb()
      .prepare('INSERT INTO sessions (session_id, did, handle, authenticated_at) VALUES (?, ?, ?, ?)')
      .run('alice', 'did:plc:alice', 'alice.example', new Date().toISOString())
  })
  after(async () => {
    await app.close()
    closeDb()
  })

  function grant() {
    const verifier = 'v'.repeat(64)
    const attempt = createAttempt({
      identifier: 'did:plc:alice',
      state: `state-${Math.random()}`,
      oauthUrl: 'https://pds.example/auth',
      returnTo: 'https://para.example/m8-auth',
      exchangeChallenge: createHash('sha256').update(verifier).digest('base64url'),
    })
    completeAttempt({ id: attempt.id, resolvedDid: 'did:plc:alice', sessionId: 'alice' })
    const { code } = createCode({ attemptId: attempt.id, sessionId: 'alice' })
    return { code, attemptId: attempt.id, verifier }
  }

  async function signIn() {
    const result = await app.inject({
      method: 'POST',
      url: '/v1/sessions/exchange',
      headers: cookieMode,
      payload: grant(),
    })
    assert.equal(result.statusCode, 200)
    return { body: JSON.parse(result.payload), cookie: refreshCookie(result.headers) }
  }

  const refresh = (cookie: string | null, headers: Record<string, string> = cookieMode) =>
    app.inject({
      method: 'POST',
      url: '/v1/sessions/refresh',
      headers: { ...headers, ...(cookie ? { cookie } : {}) },
      payload: {},
    })

  it('keeps the refresh token out of the exchange response body', async () => {
    const { body, cookie } = await signIn()
    assert.ok(body.tokens.accessToken)
    assert.equal(body.tokens.refreshToken, null)
    assert.equal(body.tokens.refreshTransport, 'cookie')
    assert.ok(cookie.pair)
    assert.match(cookie.header, /HttpOnly/i)
    assert.match(cookie.header, /SameSite=Strict/i)
  })

  it('restores a reloaded page from the cookie alone and rotates it', async () => {
    const { cookie } = await signIn()
    const result = await refresh(cookie.pair)
    assert.equal(result.statusCode, 200)
    const body = JSON.parse(result.payload)
    assert.ok(body.accessToken)
    assert.equal(body.refreshToken, null)
    assert.deepEqual(body.session, { sessionId: 'alice', did: 'did:plc:alice' })
    const next = refreshCookie(result.headers).pair
    assert.ok(next && next !== cookie.pair)
    assert.equal((await refresh(next)).statusCode, 200)
  })

  it('does not clear the cookie when another tab already rotated it', async () => {
    const { cookie } = await signIn()
    assert.equal((await refresh(cookie.pair)).statusCode, 200)
    const replay = await refresh(cookie.pair)
    assert.equal(replay.statusCode, 401)
    assert.equal(JSON.parse(replay.payload).code, 'REFRESH_TOKEN_REUSED')
    assert.equal(replay.headers['set-cookie'], undefined)
  })

  it('refuses cookie mode from an origin outside the explicit allowlist without consuming the cookie', async () => {
    const { cookie } = await signIn()
    const foreign = await refresh(cookie.pair, { origin: 'https://evil.example', 'x-m8-refresh-transport': 'cookie' })
    assert.equal(foreign.statusCode, 403)
    assert.equal(JSON.parse(foreign.payload).code, 'REFRESH_COOKIE_UNAVAILABLE')
    const missingOrigin = await refresh(cookie.pair, { 'x-m8-refresh-transport': 'cookie' })
    assert.equal(missingOrigin.statusCode, 403)
    assert.equal((await refresh(cookie.pair)).statusCode, 200)
  })

  it('ignores the cookie unless the client opts in with the transport header', async () => {
    const { cookie } = await signIn()
    const result = await refresh(cookie.pair, { origin: ORIGIN })
    assert.equal(result.statusCode, 400)
    assert.equal((await refresh(cookie.pair)).statusCode, 200)
  })

  it('refuses the exchange from a foreign origin before consuming the code', async () => {
    const valid = grant()
    const denied = await app.inject({
      method: 'POST',
      url: '/v1/sessions/exchange',
      headers: { origin: 'https://evil.example', 'x-m8-refresh-transport': 'cookie' },
      payload: valid,
    })
    assert.equal(denied.statusCode, 403)
    const allowed = await app.inject({ method: 'POST', url: '/v1/sessions/exchange', headers: cookieMode, payload: valid })
    assert.equal(allowed.statusCode, 200)
  })

  it('logout revokes the cookie credential and clears the cookie', async () => {
    const { body, cookie } = await signIn()
    const result = await app.inject({
      method: 'POST',
      url: '/v1/sessions/logout',
      headers: { ...cookieMode, cookie: cookie.pair!, authorization: `Bearer ${body.tokens.accessToken}` },
      payload: {},
    })
    assert.equal(result.statusCode, 200)
    assert.match(refreshCookie(result.headers).header, /m8_refresh=;|Max-Age=0|Expires=Thu, 01 Jan 1970/i)
    const after = await refresh(cookie.pair)
    assert.equal(after.statusCode, 401)
  })

  it('reports a missing web session without a cookie', async () => {
    const result = await refresh(null)
    assert.equal(result.statusCode, 401)
    assert.equal(JSON.parse(result.payload).code, 'NO_REFRESH_COOKIE')
  })
})
