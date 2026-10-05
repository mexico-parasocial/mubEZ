import { it } from 'node:test'
import assert from 'node:assert/strict'
import { oauthHandoffUrl, resolveOAuthHandoff } from '../../src/services/oauthHandoff.js'

const allowed = 'im8://oauth/callback,para://m8-auth,https://para.example/m8-auth,http://localhost:8081/m8-auth'
it('allows only exact configured native and web callbacks', () => {
  assert.equal(resolveOAuthHandoff('mobile', 'para://m8-auth', true, allowed), 'para://m8-auth')
  assert.equal(
    resolveOAuthHandoff('web', 'https://para.example/m8-auth', true, allowed),
    'https://para.example/m8-auth',
  )
  assert.equal(
    resolveOAuthHandoff('web', 'http://localhost:8081/m8-auth', true, allowed),
    'http://localhost:8081/m8-auth',
  )
  for (const value of [
    'https://para.example.evil/m8-auth',
    'https://para.example/m8-auth/extra',
    'para://other',
    'https://para.example/m8-auth?x=1',
  ]) {
    assert.throws(() => resolveOAuthHandoff('web', value, true, allowed), /OAUTH_RETURN_TO_INVALID/)
  }
})
it('does not permit unsafe web origins even when misconfigured into the allowlist', () => {
  for (const value of [
    'http://para.example/m8-auth',
    'para://m8-auth',
    'https://user:password@para.example/m8-auth',
    'https://para.example/m8-auth#fragment',
  ]) {
    assert.throws(() => resolveOAuthHandoff('web', value, true, value), /OAUTH_RETURN_TO_INVALID/)
  }
})
it('keeps the legacy JSON callback and mobile default while rejecting disabled explicit handoffs', () => {
  assert.equal(resolveOAuthHandoff(undefined, undefined, false, allowed), null)
  assert.equal(resolveOAuthHandoff('mobile', undefined, true, allowed), 'im8://oauth/callback')
  assert.throws(
    () => resolveOAuthHandoff('web', 'https://para.example/m8-auth', false, allowed),
    /OAUTH_HANDOFF_UNAVAILABLE/,
  )
  assert.throws(() => resolveOAuthHandoff('web', undefined, true, allowed), /OAUTH_RETURN_TO_INVALID/)
})
it('redirects carry attempt binding and code/error, never bearer credentials', () => {
  const success = new URL(oauthHandoffUrl('para://m8-auth', 'attempt-1', { code: 'm8ex-test' }))
  assert.deepEqual(Object.fromEntries(success.searchParams), { attempt_id: 'attempt-1', exchange_code: 'm8ex-test' })
  const failed = new URL(
    oauthHandoffUrl('https://para.example/m8-auth', 'attempt-1', { error: 'OAUTH_CALLBACK_FAILED' }),
  )
  assert.deepEqual(Object.fromEntries(failed.searchParams), { attempt_id: 'attempt-1', error: 'OAUTH_CALLBACK_FAILED' })
})
