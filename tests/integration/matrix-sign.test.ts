import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { bytesToHex } from '@noble/curves/abstract/utils'
import type { TestApp } from '../helpers/testApp.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-matrix-sign-http-'))
process.env.DATABASE_PATH = join(tmpDir, 'matrix-sign-http.db')

let app: TestApp
let closeDb: typeof import('../../src/db/connection.js').closeDb

const { signAssertion, sr25519PublicKey } = await import('../helpers/identitySignature.js')

// The relay checks signature-over-request, not key provenance (that is the
// wallet's job), so any in-range scalar makes a valid wallet key.
const WALLET_SCALAR = 0x2345n
const WALLET_PUB = bytesToHex(sr25519PublicKey(WALLET_SCALAR))

const AUDIENCE = 'para-matrix-bridge/join.v1'
const CHALLENGE = 'ab'.repeat(32)

async function startSession(identifier: string) {
  const res = await app.inject({
    method: 'POST',
    url: '/v1/sessions/start',
    payload: { identifier },
  })
  assert.equal(res.statusCode, 200)
  return JSON.parse(res.payload).tokens.accessToken as string
}

function signedFor(challenge: string, audience: string, overrides: Record<string, unknown> = {}) {
  const assertion = {
    type: 'para.identity.pop.v1' as const,
    purpose: 'matrix-login' as const,
    audience,
    identityPub: WALLET_PUB,
    challenge,
    signedAt: new Date().toISOString(),
    ...overrides,
  }
  return { assertion, signature: signAssertion(WALLET_SCALAR, assertion) }
}

describe('matrix sign-request relay (HTTP)', () => {
  let para: string
  let other: string

  before(async () => {
    const appModule = await import('../../src/index.js')
    const dbModule = await import('../../src/db/connection.js')
    app = await appModule.buildApp()
    closeDb = dbModule.closeDb
    para = await startSession('did:plc:matrixpara')
    other = await startSession('did:plc:matrixother')
  })

  after(async () => {
    await app.close()
    closeDb()
  })

  it('requires a session on every relay route', async () => {
    const store = await app.inject({
      method: 'POST',
      url: '/v1/matrix/sign-requests',
      payload: { challenge: CHALLENGE, audience: AUDIENCE },
    })
    assert.equal(store.statusCode, 401)

    const index = await app.inject({ method: 'GET', url: '/v1/matrix/sign-requests' })
    assert.equal(index.statusCode, 401)

    const fulfill = await app.inject({
      method: 'POST',
      url: '/v1/matrix/sign-requests/some-id/fulfill',
      payload: {},
    })
    assert.equal(fulfill.statusCode, 401)
  })

  it('validates the deposited request against the bridge audience allowlist', async () => {
    const badChallenge = await app.inject({
      method: 'POST',
      url: '/v1/matrix/sign-requests',
      headers: { authorization: `Bearer ${para}` },
      payload: { challenge: 'not-hex', audience: AUDIENCE },
    })
    assert.equal(badChallenge.statusCode, 422)

    const unknownAudience = await app.inject({
      method: 'POST',
      url: '/v1/matrix/sign-requests',
      headers: { authorization: `Bearer ${para}` },
      payload: { challenge: CHALLENGE, audience: 'para-matrix-bridge/unknown.v1' },
    })
    assert.equal(unknownAudience.statusCode, 422)

    const badSignatureLength = await app.inject({
      method: 'POST',
      url: '/v1/matrix/sign-requests/some-id/fulfill',
      headers: { authorization: `Bearer ${para}` },
      payload: { ...signedFor(CHALLENGE, AUDIENCE), signature: 'ff'.repeat(63) },
    })
    assert.equal(badSignatureLength.statusCode, 422)
  })

  it('carries a deposited challenge to the wallet and back to PARA', async () => {
    // One user session end to end: the PARA app deposits on it, the iM8
    // wallet lists and fulfills against it, PARA polls it back out.
    const created = await app.inject({
      method: 'POST',
      url: '/v1/matrix/sign-requests',
      headers: { authorization: `Bearer ${para}` },
      payload: { challenge: CHALLENGE, audience: AUDIENCE },
    })
    assert.equal(created.statusCode, 201)
    const request = JSON.parse(created.payload)
    assert.equal(request.status, 'pending')
    assert.equal(request.challenge, CHALLENGE)
    assert.equal(request.audience, AUDIENCE)
    assert.equal(request.assertion, undefined)

    // The wallet's pending list shows it; PARA's poll still sees it pending.
    const listed = await app.inject({
      method: 'GET',
      url: '/v1/matrix/sign-requests',
      headers: { authorization: `Bearer ${para}` },
    })
    assert.equal(listed.statusCode, 200)
    assert.ok(
      JSON.parse(listed.payload).requests.some((r: { id: string }) => r.id === request.id),
    )

    const poll = await app.inject({
      method: 'GET',
      url: `/v1/matrix/sign-requests/${request.id}`,
      headers: { authorization: `Bearer ${para}` },
    })
    assert.equal(poll.statusCode, 200)
    assert.equal(JSON.parse(poll.payload).status, 'pending')

    // Unknown ids are 404, not a leak.
    const missing = await app.inject({
      method: 'GET',
      url: `/v1/matrix/sign-requests/00000000-0000-0000-0000-000000000000`,
      headers: { authorization: `Bearer ${para}` },
    })
    assert.equal(missing.statusCode, 404)

    const fulfill = await app.inject({
      method: 'POST',
      url: `/v1/matrix/sign-requests/${request.id}/fulfill`,
      headers: { authorization: `Bearer ${para}` },
      payload: signedFor(CHALLENGE, AUDIENCE),
    })
    assert.equal(fulfill.statusCode, 200)
    assert.deepEqual(JSON.parse(fulfill.payload), { status: 'fulfilled' })

    const after = await app.inject({
      method: 'GET',
      url: `/v1/matrix/sign-requests/${request.id}`,
      headers: { authorization: `Bearer ${para}` },
    })
    assert.equal(after.statusCode, 200)
    const stored = JSON.parse(after.payload)
    assert.equal(stored.status, 'fulfilled')
    assert.equal(stored.assertion.assertion.identityPub, WALLET_PUB)
  })

  it('refuses a signature over anything but exactly the deposited challenge', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/v1/matrix/sign-requests',
      headers: { authorization: `Bearer ${para}` },
      payload: { challenge: 'cd'.repeat(32), audience: AUDIENCE },
    })
    const request = JSON.parse(created.payload)

    // Signed for a different challenge than the request carries.
    const wrongChallenge = await app.inject({
      method: 'POST',
      url: `/v1/matrix/sign-requests/${request.id}/fulfill`,
      headers: { authorization: `Bearer ${para}` },
      payload: signedFor('ef'.repeat(32), AUDIENCE),
    })
    assert.equal(wrongChallenge.statusCode, 400)
    assert.equal(JSON.parse(wrongChallenge.payload).error, 'invalid-proof')

    // Wrong bridge audience on an otherwise correct signature.
    const wrongAudience = await app.inject({
      method: 'POST',
      url: `/v1/matrix/sign-requests/${request.id}/fulfill`,
      headers: { authorization: `Bearer ${para}` },
      payload: signedFor('cd'.repeat(32), 'para-matrix-bridge/identity.v1'),
    })
    assert.equal(wrongAudience.statusCode, 400)

    // Garbage that fakes the shape still fails verification, not validation.
    const forged = await app.inject({
      method: 'POST',
      url: `/v1/matrix/sign-requests/${request.id}/fulfill`,
      headers: { authorization: `Bearer ${para}` },
      payload: signedFor('cd'.repeat(32), AUDIENCE, { identityPub: '00'.repeat(32) }),
    })
    assert.equal(forged.statusCode, 400)

    const poll = await app.inject({
      method: 'GET',
      url: `/v1/matrix/sign-requests/${request.id}`,
      headers: { authorization: `Bearer ${para}` },
    })
    assert.equal(JSON.parse(poll.payload).status, 'pending')
  })

  it('keeps requests session-bound end to end', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/v1/matrix/sign-requests',
      headers: { authorization: `Bearer ${para}` },
      payload: { challenge: '12'.repeat(32), audience: AUDIENCE },
    })
    const request = JSON.parse(created.payload)

    // Another session cannot see, poll, or fulfill it — not even with a
    // signature that verifies against the request's challenge.
    const foreignList = await app.inject({
      method: 'GET',
      url: '/v1/matrix/sign-requests',
      headers: { authorization: `Bearer ${other}` },
    })
    assert.equal(
      JSON.parse(foreignList.payload).requests.some((r: { id: string }) => r.id === request.id),
      false,
    )

    const foreignFulfill = await app.inject({
      method: 'POST',
      url: `/v1/matrix/sign-requests/${request.id}/fulfill`,
      headers: { authorization: `Bearer ${other}` },
      payload: signedFor('12'.repeat(32), AUDIENCE),
    })
    assert.equal(foreignFulfill.statusCode, 404)

    // The owning session fulfills; a second fulfillment is refused.
    const fulfill = await app.inject({
      method: 'POST',
      url: `/v1/matrix/sign-requests/${request.id}/fulfill`,
      headers: { authorization: `Bearer ${para}` },
      payload: signedFor('12'.repeat(32), AUDIENCE),
    })
    assert.equal(fulfill.statusCode, 200)
    const again = await app.inject({
      method: 'POST',
      url: `/v1/matrix/sign-requests/${request.id}/fulfill`,
      headers: { authorization: `Bearer ${para}` },
      payload: signedFor('12'.repeat(32), AUDIENCE),
    })
    assert.equal(again.statusCode, 400)
    assert.equal(JSON.parse(again.payload).error, 'not-pending')
  })
})
