import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-gates-test-'))
process.env.DATABASE_PATH = join(tmpDir, 'gates-test.db')
process.env.GROWTHBOOK_FEATURE_OVERRIDES = JSON.stringify({
  'm8:auth:dev_token_bootstrap': true,
  'm8:demo_identity_wallet:enable': false,
  'm8:simulated_ine:enable': false,
  'm8:development_device_trust:enable': false,
  'm8:local_para_fallback:enable': false,
  'm8:local_trust_policy:enable': false,
})

describe('GrowthBook safety gates', () => {
  let app: TestApp
  let accessToken: string

  before(async () => {
    const { buildApp } = await import('../../src/index.js')
    app = await buildApp()
    const start = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'gated-demo.bsky.social' },
    })
    const body = JSON.parse(start.payload)
    accessToken = body.tokens.accessToken
  })

  after(async () => {
    await app.close()
  })

  it('blocks demo wallet presentations when the demo wallet gate is off', async () => {
    const request = await app.inject({
      method: 'POST',
      url: '/v1/identity/request',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        audienceAppId: 'gated-app',
        audienceAppName: 'Gated App',
        purpose: 'Verify gated wallet behavior.',
        requestedElements: [
          { id: 'age_over_18', intentToStore: { mode: 'will-not-store' }, required: true },
        ],
      },
    })
    const requestBody = JSON.parse(request.payload)

    const present = await app.inject({
      method: 'POST',
      url: '/v1/identity/present',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { requestId: requestBody.id, subjectDid: 'did:plc:gated' },
    })

    assert.equal(present.statusCode, 404)
    assert.equal(JSON.parse(present.payload).code, 'FEATURE_DISABLED')
  })

  it('blocks simulated INE and development device trust when their gates are off', async () => {
    const ine = await app.inject({
      method: 'POST',
      url: '/v1/identity/ine/analyze',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { inePhotoBase64: 'mock-photo' },
    })
    assert.equal(ine.statusCode, 404)
    assert.equal(JSON.parse(ine.payload).code, 'FEATURE_DISABLED')

    const device = await app.inject({
      method: 'POST',
      url: '/v1/device-trust/development/verify',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { platform: 'ios', deviceKeyId: 'test-device' },
    })
    assert.equal(device.statusCode, 404)
    assert.equal(JSON.parse(device.payload).code, 'FEATURE_DISABLED')
  })

  it('does not let local PARA fallback or local trust policy verify claims', async () => {
    const paraStatus = await app.inject({
      method: 'GET',
      url: '/v1/providers/para/status',
      headers: { authorization: `Bearer ${accessToken}` },
    })
    assert.equal(JSON.parse(paraStatus.payload).availability, 'offline')

    const grantRequest = await app.inject({
      method: 'POST',
      url: '/v1/grants',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        appId: 'gated-app',
        appName: 'Gated App',
        appKind: 'Civic app',
        surface: 'civic',
        requestedClaims: [{ type: 'is_civic_eligible', disclosure: 'proof-only' }],
        proofMode: 'proof-only',
        reason: 'Should not verify while local trust policy is disabled.',
      },
    })
    const grantId = JSON.parse(grantRequest.payload).grant.id

    const approved = await app.inject({
      method: 'POST',
      url: `/v1/grants/${encodeURIComponent(grantId)}/approve`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {},
    })
    const proof = JSON.parse(approved.payload).proofs[0]
    assert.equal(proof.outcome, 'not-verified')
    assert.match(proof.statement, /disabled/i)
  })
})
