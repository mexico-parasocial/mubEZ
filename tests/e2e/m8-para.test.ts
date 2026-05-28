import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-test-'))
process.env.DATABASE_PATH = join(tmpDir, 'test.db')

let buildApp: typeof import('../../src/index.js').buildApp
let closeDb: typeof import('../../src/db/connection.js').closeDb

describe('m8 ↔ para cross-service e2e', () => {
  let app: TestApp
  let accessToken: string
  let sessionId: string

  before(async () => {
    ;({ buildApp } = await import('../../src/index.js'))
    ;({ closeDb } = await import('../../src/db/connection.js'))
    app = await buildApp()
    const start = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'e2e-user.bsky.social' },
    })
    const body = JSON.parse(start.payload)
    accessToken = body.tokens.accessToken
    sessionId = body.attempt.sessionId
  })

  after(async () => {
    await app.close()
    closeDb()
  })

  it('full flow: session → grant → approve → identity request → present → verify', async () => {
    // 1. Start session (done in before)
    assert.ok(accessToken)
    assert.ok(sessionId)

    // 2. Request a grant
    const grantRes = await app.inject({
      method: 'POST',
      url: '/v1/grants',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        appId: 'para.app',
        appName: 'PARA App',
        appKind: 'Civic app',
        surface: 'civic',
        requestedClaims: [
          { type: 'has_para_verification', disclosure: 'proof-only' },
          { type: 'is_verified_public_figure', disclosure: 'proof-only' },
        ],
        proofMode: 'proof-only',
        reason: 'E2E test grant',
      },
    })
    assert.equal(grantRes.statusCode, 201)
    const grantBody = JSON.parse(grantRes.payload)
    assert.equal(grantBody.grant.status, 'pending')

    // 3. Approve the grant
    const approveRes = await app.inject({
      method: 'POST',
      url: `/v1/grants/${grantBody.grant.id}/approve`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { grantId: grantBody.grant.id, reviewNote: 'E2E approved' },
    })
    assert.equal(approveRes.statusCode, 200)
    const approveBody = JSON.parse(approveRes.payload)
    assert.equal(approveBody.grant.status, 'approved')
    assert.equal(approveBody.proofs.length, 2)

    // 4. Create identity request
    const idReqRes = await app.inject({
      method: 'POST',
      url: '/v1/identity/request',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        audienceAppId: 'test.merchant',
        audienceAppName: 'Test Merchant',
        purpose: 'E2E identity verification',
        requestedElements: [
          { id: 'age_over_18', intentToStore: { mode: 'will-not-store' }, required: true },
          { id: 'citizenship', intentToStore: { mode: 'will-not-store' }, required: false },
        ],
      },
    })
    assert.equal(idReqRes.statusCode, 201)
    const idReq = JSON.parse(idReqRes.payload)
    assert.equal(idReq.status, 'active')

    // 5. Create wallet presentation
    const presRes = await app.inject({
      method: 'POST',
      url: '/v1/identity/present',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        requestId: idReq.id,
        subjectDid: 'did:plc:e2e123',
        selectedElementIds: ['age_over_18', 'citizenship'],
      },
    })
    assert.equal(presRes.statusCode, 200)
    const presentation = JSON.parse(presRes.payload)
    assert.ok(presentation.credential)
    assert.ok(presentation.signature)

    // 6. Verify presentation
    const verifyRes = await app.inject({
      method: 'POST',
      url: '/v1/identity/verify',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        requestId: idReq.id,
        presentation,
      },
    })
    assert.equal(verifyRes.statusCode, 200)
    const verifyBody = JSON.parse(verifyRes.payload)
    assert.equal(verifyBody.valid, true)
    assert.equal(verifyBody.errors.length, 0)
    assert.ok(verifyBody.disclosedClaims.age_over_18)
    assert.ok(verifyBody.disclosedClaims.citizenship)

    // 7. Check PARA provider status
    const paraRes = await app.inject({
      method: 'GET',
      url: '/v1/providers/para/status',
      headers: { authorization: `Bearer ${accessToken}` },
    })
    assert.equal(paraRes.statusCode, 200)
    const paraBody = JSON.parse(paraRes.payload)
    assert.equal(paraBody.providerId, 'para.identity')
    assert.ok(paraBody.supportedClaims.length > 0)
  })
})
