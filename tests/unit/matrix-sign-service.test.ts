import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { bytesToHex } from '@noble/curves/abstract/utils'

// The service opens SQLite lazily via getDb(); point it at a temp database
// before the first import touches it.
process.env.DATABASE_PATH = join(mkdtempSync(join(tmpdir(), 'mubez-sign-')), 'db.sqlite')

const { signAssertion, sr25519PublicKey } = await import('../helpers/identitySignature.js')
const {
  createMatrixSignRequest,
  listPendingMatrixSignRequests,
  getMatrixSignRequest,
  fulfillMatrixSignRequest,
} = await import('../../src/services/matrixSignService.js')

// Any in-range scalar makes a valid key pair for the verifier — the relay
// checks signature-over-request, not key provenance (that is the wallet's job).
const TEST_SCALAR = 0x1234n
const TEST_PUB = bytesToHex(sr25519PublicKey(TEST_SCALAR))

const SESSION = 'sess-test-1'
const AUDIENCE = 'para-matrix-bridge/join.v1'
const CHALLENGE = 'a'.repeat(64)

function signedFor(challenge: string, audience: string) {
  const assertion = {
    type: 'para.identity.pop.v1' as const,
    purpose: 'matrix-login' as const,
    audience,
    identityPub: TEST_PUB,
    challenge,
    signedAt: new Date().toISOString(),
  }
  return { assertion, signature: signAssertion(TEST_SCALAR, assertion) }
}

describe('matrix sign-request relay', () => {
  before(() => {
    // Warm the module so schema creation happens against the temp database.
    listPendingMatrixSignRequests(SESSION)
  })

  it('creates a pending request bound to the session', () => {
    const request = createMatrixSignRequest(SESSION, {
      challenge: CHALLENGE,
      audience: AUDIENCE,
    })
    assert.equal(request.status, 'pending')
    assert.equal(request.challenge, CHALLENGE)
    assert.equal(request.audience, AUDIENCE)

    // Visible on the wallet's pending list for the same session only.
    assert.equal(listPendingMatrixSignRequests(SESSION).length, 1)
    assert.equal(listPendingMatrixSignRequests('sess-other').length, 0)
  })

  it('rejects a fulfillment whose signature does not verify', () => {
    const request = createMatrixSignRequest(SESSION, {
      challenge: 'b'.repeat(64),
      audience: AUDIENCE,
    })
    // Signed for a different challenge than the request carries.
    const wrongChallenge = signedFor(CHALLENGE, AUDIENCE)
    const bad = fulfillMatrixSignRequest(SESSION, request.id, wrongChallenge)
    assert.deepEqual(bad, { ok: false, reason: 'invalid-proof' })

    // Still pending, nothing stored.
    assert.equal(
      (getMatrixSignRequest(SESSION, request.id) as { status: string }).status,
      'pending',
    )
  })

  it('stores the assertion only after it verifies against the request', () => {
    const request = createMatrixSignRequest(SESSION, {
      challenge: 'c'.repeat(64),
      audience: AUDIENCE,
    })
    const ok = fulfillMatrixSignRequest(
      SESSION,
      request.id,
      signedFor('c'.repeat(64), AUDIENCE),
    )
    assert.deepEqual(ok, { ok: true })

    const stored = getMatrixSignRequest(SESSION, request.id)
    assert.equal(stored?.status, 'fulfilled')
    assert.equal(stored?.assertion?.assertion.challenge, 'c'.repeat(64))

    // Not pending anymore, and a second fulfillment is refused.
    const pendingIds = listPendingMatrixSignRequests(SESSION).map((r) => r.id)
    assert.ok(!pendingIds.includes(request.id))
    const again = fulfillMatrixSignRequest(
      SESSION,
      request.id,
      signedFor('c'.repeat(64), AUDIENCE),
    )
    assert.equal(again.ok, false)
  })

  it('never returns another session\'s request', () => {
    const request = createMatrixSignRequest('sess-a', {
      challenge: 'd'.repeat(64),
      audience: AUDIENCE,
    })
    assert.equal(getMatrixSignRequest('sess-b', request.id), undefined)
    const foreign = fulfillMatrixSignRequest(
      'sess-b',
      request.id,
      signedFor('d'.repeat(64), AUDIENCE),
    )
    assert.deepEqual(foreign, { ok: false, reason: 'not-found' })
  })
})
