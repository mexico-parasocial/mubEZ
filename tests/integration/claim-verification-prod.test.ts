import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createServer, type Server } from 'node:http'
import { type AddressInfo } from 'node:net'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-claim-prod-test-'))
process.env.DATABASE_PATH = join(tmpDir, 'claim-prod-test.db')
// Production posture: no demo trust policy, no local PARA fallback. The
// honest upstream result must always stand.
process.env.GROWTHBOOK_FEATURE_OVERRIDES = JSON.stringify({
  'm8:local_trust_policy:enable': false,
  'm8:local_para_fallback:enable': false,
})

let stubMode: 'echo' | 'other' = 'echo'
let paraStub: Server

describe('claim verification routing (production posture)', () => {
  let app: TestApp
  let accessToken: string

  before(async () => {
    paraStub = createServer((req, res) => {
      const url = new URL(req.url ?? '/', 'http://localhost')
      const actor = url.searchParams.get('actor') ?? ''
      res.setHeader('content-type', 'application/json')
      res.end(
        JSON.stringify({
          did: stubMode === 'echo' ? actor : 'did:plc:not-the-subject',
          handle: actor,
          verification: { verified: true },
        }),
      )
    })
    await new Promise<void>((resolve) => paraStub.listen(0, '127.0.0.1', resolve))
    process.env.PARA_API_BASE_URL = `http://127.0.0.1:${(paraStub.address() as AddressInfo).port}`

    const { buildApp } = await import('../../src/index.js')
    app = await buildApp()
    const start = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'prod-user.bsky.social' },
    })
    accessToken = JSON.parse(start.payload).tokens.accessToken
  })

  after(async () => {
    await app.close()
    if (paraStub.listening) {
      await new Promise<void>((resolve) => paraStub.close(() => resolve()))
    }
  })

  async function requestAndApprove(claimType: string) {
    const request = await app.inject({
      method: 'POST',
      url: '/v1/grants',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        appId: 'test-app',
        appName: 'Test App',
        appKind: 'Civic app',
        surface: 'civic',
        requestedClaims: [{ type: claimType, disclosure: 'proof-only' }],
        proofMode: 'proof-only',
        reason: 'test grant',
      },
    })
    assert.equal(request.statusCode, 201)
    const grant = JSON.parse(request.payload).grant
    const approve = await app.inject({
      method: 'POST',
      url: `/v1/grants/${grant.id}/approve`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {},
    })
    assert.equal(approve.statusCode, 200)
    const proofs = JSON.parse(approve.payload).proofs
    assert.equal(proofs.length, 1)
    return proofs[0]
  }

  it('verifies live via the PARA network in production posture', async () => {
    stubMode = 'echo'
    const proof = await requestAndApprove('has_para_verification')
    assert.equal(proof.outcome, 'verified')
    assert.equal(proof.verifierId, 'para.identity')
    assert.match(proof.statement, /PARA API confirms/)
  })

  it('rejects a PARA result bound to a different DID (issuer_not_trusted)', async () => {
    stubMode = 'other'
    const proof = await requestAndApprove('has_para_verification')
    assert.equal(proof.outcome, 'not-verified')
    assert.match(proof.statement, /issuer_not_trusted/)
    stubMode = 'echo'
  })

  it('hard-fails PARA claims when the API is unreachable (no silent fallback)', async () => {
    await new Promise<void>((resolve) => paraStub.close(() => resolve()))
    const proof = await requestAndApprove('has_para_verification')
    assert.equal(proof.outcome, 'not-verified')
    assert.doesNotMatch(proof.statement, /demo trust policy/)
    // (subsequent test in this file does not use the PARA stub)
  })

  it('does not derive civic eligibility without an INE commitment', async () => {
    const proof = await requestAndApprove('is_civic_eligible')
    assert.equal(proof.outcome, 'not-verified')
    assert.match(proof.statement, /No active INE identity commitment/)
  })
})
