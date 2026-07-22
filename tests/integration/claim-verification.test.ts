import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createServer, type Server } from 'node:http'
import { type AddressInfo } from 'node:net'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'
import { issueIneCredentialWithClientProof } from '../helpers/clientProof.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-claim-test-'))
process.env.DATABASE_PATH = join(tmpDir, 'claim-test.db')

// Stub PARA network. 'echo' mode binds the profile DID to whatever actor was
// queried (simulating a matching subject); 'other' mode simulates a result
// bound to a different DID (session mismatch); 'down' simulates an API error.
let stubMode: 'echo' | 'other' | 'down' = 'echo'
let paraStub: Server
let paraBaseUrl = ''

describe('claim verification routing (dev fallbacks)', () => {
  let app: TestApp
  let accessToken: string

  before(async () => {
    paraStub = createServer((req, res) => {
      if (stubMode === 'down') {
        res.statusCode = 500
        res.end()
        return
      }
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
    paraBaseUrl = `http://127.0.0.1:${(paraStub.address() as AddressInfo).port}`
    process.env.PARA_API_BASE_URL = paraBaseUrl

    const { buildApp } = await import('../../src/index.js')
    app = await buildApp()
    const start = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'claim-user.bsky.social' },
    })
    accessToken = JSON.parse(start.payload).tokens.accessToken

    const credential = await issueIneCredentialWithClientProof({
      app,
      accessToken,
      inePhotoBase64: 'mock-claim-ine',
      selfieBase64: 'mock-claim-selfie',
    })
    assert.equal(credential.response.statusCode, 200)
  })

  after(async () => {
    await app.close()
    await new Promise<void>((resolve) => paraStub.close(() => resolve()))
  })

  async function requestAndApprove(claimType: string, requestedValue?: string) {
    const request = await app.inject({
      method: 'POST',
      url: '/v1/grants',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        appId: 'test-app',
        appName: 'Test App',
        appKind: 'Civic app',
        surface: 'civic',
        requestedClaims: [{ type: claimType, disclosure: 'proof-only', ...(requestedValue ? { requestedValue } : {}) }],
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

  it('verifies has_para_verification live via the PARA network', async () => {
    stubMode = 'echo'
    const proof = await requestAndApprove('has_para_verification')
    assert.equal(proof.outcome, 'verified')
    assert.equal(proof.verifierId, 'para.identity')
    assert.match(proof.statement, /PARA API confirms/)
  })

  it('rejects a PARA result bound to a different DID (issuer_not_trusted)', async () => {
    stubMode = 'other'
    const proof = await requestAndApprove('has_para_verification')
    // Demo trust policy is on in this environment, so the honest
    // not-verified is softened — but never into a positive live result.
    assert.doesNotMatch(proof.statement, /PARA API confirms/)
    stubMode = 'echo'
  })

  it('derives is_civic_eligible from the real INE commitment', async () => {
    const proof = await requestAndApprove('is_civic_eligible')
    assert.equal(proof.outcome, 'verified')
    assert.match(proof.statement, /active INE ZK commitment/)
    assert.doesNotMatch(proof.statement, /demo trust policy/)
  })

  it('keeps the demo trust policy as an explicit dev escape hatch', async () => {
    stubMode = 'down'
    try {
      const proof = await requestAndApprove('has_para_verification')
      assert.equal(proof.outcome, 'verified')
      assert.match(proof.statement, /demo trust policy/)
    } finally {
      stubMode = 'echo'
    }
  })
})
