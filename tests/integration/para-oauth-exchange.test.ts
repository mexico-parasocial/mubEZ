import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'

process.env.DATABASE_PATH = join(mkdtempSync(join(tmpdir(), 'para-oauth-test-')), 'test.db')
process.env.GROWTHBOOK_FEATURE_OVERRIDES = JSON.stringify({
  'm8:auth:dev_token_bootstrap': false,
  'm8:auth:oauth_mobile_handoff': true,
})
process.env.OAUTH_RETURN_TO_ALLOWLIST = 'para://m8-auth,https://para.example/m8-auth'

describe('PARA OAuth exchange and device logout (seeded completed OAuth fixtures)', () => {
  let app: TestApp
  let getDb: typeof import('../../src/db/connection.js').getDb
  let closeDb: typeof import('../../src/db/connection.js').closeDb
  let createAttempt: typeof import('../../src/services/oauthLoginAttempts.js').createOAuthLoginAttempt
  let completeAttempt: typeof import('../../src/services/oauthLoginAttempts.js').completeOAuthLoginAttempt
  let createCode: typeof import('../../src/services/oauthExchangeCodes.js').createExchangeCode
  let issue: typeof import('../../src/services/tokenService.js').issueTokenBundle
  let rotate: typeof import('../../src/services/tokenService.js').rotateRefreshToken
  let revoke: typeof import('../../src/services/tokenService.js').revokeRefreshToken
  before(async () => {
    const { buildApp } = await import('../../src/index.js')
    app = await buildApp()
    ;({ getDb, closeDb } = await import('../../src/db/connection.js'))
    ;({ createOAuthLoginAttempt: createAttempt, completeOAuthLoginAttempt: completeAttempt } =
      await import('../../src/services/oauthLoginAttempts.js'))
    ;({ createExchangeCode: createCode } = await import('../../src/services/oauthExchangeCodes.js'))
    ;({
      issueTokenBundle: issue,
      rotateRefreshToken: rotate,
      revokeRefreshToken: revoke,
    } = await import('../../src/services/tokenService.js'))
    for (const id of ['alice', 'bob'])
      getDb()
        .prepare('INSERT INTO sessions (session_id, did, handle, authenticated_at) VALUES (?, ?, ?, ?)')
        .run(id, `did:plc:${id}`, `${id}.example`, new Date().toISOString())
  })
  after(async () => {
    await app.close()
    closeDb()
  })
  function grant(binding = true) {
    const verifier = 'v'.repeat(64)
    const attempt = createAttempt({
      identifier: 'did:plc:alice',
      state: `state-${Math.random()}`,
      oauthUrl: 'https://pds.example/auth',
      returnTo: 'para://m8-auth',
      exchangeChallenge: binding ? createHash('sha256').update(verifier).digest('base64url') : undefined,
    })
    completeAttempt({ id: attempt.id, resolvedDid: 'did:plc:alice', sessionId: 'alice' })
    const { code } = createCode({ attemptId: attempt.id, sessionId: 'alice' })
    return { code, attemptId: attempt.id, verifier }
  }
  it('rejects mismatched attempts and missing/wrong verifiers without consuming the code', async () => {
    const valid = grant()
    for (const payload of [
      { ...valid, attemptId: 'different' },
      { code: valid.code, attemptId: valid.attemptId },
      { ...valid, verifier: 'w'.repeat(64) },
    ]) {
      const result = await app.inject({ method: 'POST', url: '/v1/sessions/exchange', payload })
      assert.equal(result.statusCode, 400)
      assert.equal(JSON.parse(result.payload).code, 'OAUTH_EXCHANGE_INVALID')
    }
    const success = await app.inject({ method: 'POST', url: '/v1/sessions/exchange', payload: valid })
    assert.equal(success.statusCode, 200)
    const body = JSON.parse(success.payload)
    assert.equal(body.attemptId, valid.attemptId)
    assert.equal(body.session.did, 'did:plc:alice')
    assert.ok(body.tokens.accessToken)
    const replay = await app.inject({ method: 'POST', url: '/v1/sessions/exchange', payload: valid })
    assert.equal(replay.statusCode, 403)
  })
  it('keeps existing clients compatible during rollout', async () => {
    const valid = grant(false)
    const result = await app.inject({ method: 'POST', url: '/v1/sessions/exchange', payload: { code: valid.code } })
    assert.equal(result.statusCode, 200)
  })
  it('retains the code verifier binding even after its audit attempt is removed', async () => {
    const valid = grant()
    getDb().prepare('DELETE FROM oauth_login_attempts WHERE id = ?').run(valid.attemptId)
    const denied = await app.inject({
      method: 'POST',
      url: '/v1/sessions/exchange',
      payload: { code: valid.code, attemptId: valid.attemptId },
    })
    assert.equal(denied.statusCode, 400)
    const allowed = await app.inject({ method: 'POST', url: '/v1/sessions/exchange', payload: valid })
    assert.equal(allowed.statusCode, 200)
  })
  it('returns provider failure to the configured web callback without provider details or tokens', async () => {
    const attempt = createAttempt({
      identifier: 'did:plc:alice',
      state: 'failed-provider-state',
      oauthUrl: 'https://pds.example/auth',
      returnTo: 'https://para.example/m8-auth',
    })
    const result = await app.inject({
      method: 'GET',
      url: '/v1/sessions/oauth/callback?state=failed-provider-state&error=access_denied&error_description=private-provider-detail',
      redirect: 'manual',
    })
    assert.equal(result.statusCode, 302)
    const target = new URL(result.headers.location)
    assert.equal(target.origin, 'https://para.example')
    assert.deepEqual(Object.fromEntries(target.searchParams), {
      attempt_id: attempt.id,
      error: 'OAUTH_CALLBACK_FAILED',
    })
    assert.ok(!result.payload.includes('private-provider-detail'))
  })
  it('does not redirect an unknown callback state', async () => {
    const result = await app.inject({
      method: 'GET',
      url: '/v1/sessions/oauth/callback?state=unknown&error=access_denied',
      redirect: 'manual',
    })
    assert.equal(result.statusCode, 400)
    assert.equal(result.headers.location, undefined)
  })
  it('rejects an expired code', async () => {
    const valid = grant()
    getDb()
      .prepare('UPDATE oauth_exchange_codes SET expires_at = ? WHERE attempt_id = ?')
      .run('2000-01-01T00:00:00.000Z', valid.attemptId)
    const result = await app.inject({ method: 'POST', url: '/v1/sessions/exchange', payload: valid })
    assert.equal(result.statusCode, 400)
  })
  it('rejects an unconfigured callback before creating an OAuth attempt or session', async () => {
    const count = () =>
      (getDb().prepare('SELECT COUNT(*) count FROM oauth_login_attempts').get() as { count: number }).count
    const previous = count()
    const result = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'did:plc:alice', platform: 'web', returnTo: 'https://evil.example/m8-auth' },
    })
    assert.equal(result.statusCode, 422)
    assert.equal(JSON.parse(result.payload).code, 'OAUTH_RETURN_TO_INVALID')
    assert.equal(count(), previous)
  })
  it('logout requires authentication and cannot revoke another account', async () => {
    const alice = await issue('alice')
    const bob = await issue('bob')
    const denied = await app.inject({
      method: 'POST',
      url: '/v1/sessions/logout',
      payload: { refreshToken: alice.refreshToken },
    })
    assert.equal(denied.statusCode, 401)
    await app.inject({
      method: 'POST',
      url: '/v1/sessions/logout',
      headers: { authorization: `Bearer ${alice.accessToken}` },
      payload: { refreshToken: bob.refreshToken },
    })
    assert.ok((await rotate(bob.refreshToken)).refreshToken)
  })
  it('logout revokes this rotated credential family and leaves other devices signed in', async () => {
    const first = await issue('alice')
    const other = await issue('alice')
    const rotated = await rotate(first.refreshToken)
    const result = await app.inject({
      method: 'POST',
      url: '/v1/sessions/logout',
      headers: { authorization: `Bearer ${first.accessToken}` },
      payload: { refreshToken: first.refreshToken },
    })
    assert.equal(result.statusCode, 200)
    await assert.rejects(rotate(rotated.refreshToken), /Invalid refresh token/)
    assert.ok((await rotate(other.refreshToken)).refreshToken)
  })
  it('a refresh already signing its JWT cannot create credentials after revocation', async () => {
    const first = await issue('alice')
    const refresh = rotate(first.refreshToken)
    revoke(first.refreshToken, 'alice')
    await assert.rejects(refresh, /Invalid refresh token/)
  })
  it('simultaneous refreshes have one winner', async () => {
    const first = await issue('alice')
    const results = await Promise.allSettled([rotate(first.refreshToken), rotate(first.refreshToken)])
    assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1)
    assert.equal(results.filter((r) => r.status === 'rejected').length, 1)
  })
})
