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

describe('identity wallet integration', () => {
  let app: TestApp
  let accessToken: string

  before(async () => {
    ;({ buildApp } = await import('../../src/index.js'))
    ;({ closeDb } = await import('../../src/db/connection.js'))
    app = await buildApp()
    const start = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'walletuser.bsky.social' },
    })
    const body = JSON.parse(start.payload)
    accessToken = body.tokens.accessToken
  })

  after(async () => {
    await app.close()
    closeDb()
  })

  it('POST /v1/identity/request creates an identity request', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/identity/request',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        audienceAppId: 'test.merchant',
        audienceAppName: 'Test Merchant',
        purpose: 'Age verification',
        requestedElements: [
          { id: 'age_over_18', intentToStore: { mode: 'will-not-store' }, required: true },
        ],
      },
    })

    assert.equal(res.statusCode, 201)
    const body = JSON.parse(res.payload)
    assert.ok(body.id.startsWith('identity-request-'))
    assert.equal(body.status, 'active')
    assert.ok(body.nonce)
  })

  it('POST /v1/identity/present creates a wallet presentation', async () => {
    const reqRes = await app.inject({
      method: 'POST',
      url: '/v1/identity/request',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        audienceAppId: 'test.merchant',
        audienceAppName: 'Test Merchant',
        purpose: 'Age verification',
        requestedElements: [
          { id: 'age_over_18', intentToStore: { mode: 'will-not-store' }, required: true },
        ],
      },
    })
    const request = JSON.parse(reqRes.payload)

    const res = await app.inject({
      method: 'POST',
      url: '/v1/identity/present',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        requestId: request.id,
        subjectDid: 'did:plc:test123',
      },
    })

    assert.equal(res.statusCode, 200)
    const body = JSON.parse(res.payload)
    assert.equal(body.type, 'm8.identity.presentation.v1')
    assert.ok(body.credential.signature)
    assert.ok(body.signature)
  })

  it('POST /v1/identity/verify validates a presentation', async () => {
    const reqRes = await app.inject({
      method: 'POST',
      url: '/v1/identity/request',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        audienceAppId: 'test.merchant',
        audienceAppName: 'Test Merchant',
        purpose: 'Age verification',
        requestedElements: [
          { id: 'age_over_18', intentToStore: { mode: 'will-not-store' }, required: true },
        ],
      },
    })
    const request = JSON.parse(reqRes.payload)

    const presRes = await app.inject({
      method: 'POST',
      url: '/v1/identity/present',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        requestId: request.id,
        subjectDid: 'did:plc:test123',
      },
    })
    const presentation = JSON.parse(presRes.payload)

    const res = await app.inject({
      method: 'POST',
      url: '/v1/identity/verify',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        requestId: request.id,
        presentation,
      },
    })

    assert.equal(res.statusCode, 200)
    const body = JSON.parse(res.payload)
    assert.equal(body.valid, true)
    assert.equal(body.errors.length, 0)
  })
})
