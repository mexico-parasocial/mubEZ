import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'
import { issueIneCredentialWithClientProof } from '../helpers/clientProof.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-karma-test-'))
process.env.DATABASE_PATH = join(tmpDir, 'karma-test.db')

describe('server-derived karma', () => {
  let app: TestApp
  let accessToken: string

  before(async () => {
    const { buildApp } = await import('../../src/index.js')
    app = await buildApp()
    const start = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'karma-user.bsky.social' },
    })
    accessToken = JSON.parse(start.payload).tokens.accessToken

    // Karma earning requires an anonymous profile; the credential flow
    // creates one and also unlocks the INE-dependent actions.
    const credential = await issueIneCredentialWithClientProof({
      app,
      accessToken,
      inePhotoBase64: 'mock-karma-ine',
      selfieBase64: 'mock-karma-selfie',
    })
    assert.equal(credential.response.statusCode, 200)
  })

  after(async () => {
    await app.close()
  })

  it('derives points server-side and ignores client-sent points', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/karma/earn',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { actionType: 'ine_credential_issued', points: 9999 },
    })

    assert.equal(res.statusCode, 200)
    const body = JSON.parse(res.payload)
    assert.equal(body.earned, true)
    assert.equal(body.points, 10)
  })

  it('rejects duplicate awards for the same action', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/karma/earn',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { actionType: 'ine_credential_issued' },
    })

    assert.equal(res.statusCode, 409)
    assert.equal(JSON.parse(res.payload).code, 'KARMA_ALREADY_AWARDED')
  })

  it('rejects actions the server cannot verify', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/karma/earn',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        actionType: 'civic_vote_cast',
        detail: { subjectUri: 'at://did:plc:example/com.para.civic.cabildeo/never-voted' },
      },
    })

    assert.equal(res.statusCode, 403)
    assert.equal(JSON.parse(res.payload).code, 'KARMA_ACTION_NOT_VERIFIED')
  })

  it('rejects unknown actions and missing subjects', async () => {
    const unknown = await app.inject({
      method: 'POST',
      url: '/v1/karma/earn',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { actionType: 'definitely_not_real' },
    })
    assert.equal(unknown.statusCode, 400)
    assert.equal(JSON.parse(unknown.payload).code, 'UNKNOWN_KARMA_ACTION')

    const missing = await app.inject({
      method: 'POST',
      url: '/v1/karma/earn',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { actionType: 'civic_vote_cast' },
    })
    assert.equal(missing.statusCode, 400)
    assert.equal(JSON.parse(missing.payload).code, 'KARMA_SUBJECT_REQUIRED')
  })

  it('awards karma for a verified vote and reflects it in /karma/me', async () => {
    const subjectUri = 'at://did:plc:example/com.para.civic.cabildeo/karma-vote'
    const proof = await app.inject({
      method: 'POST',
      url: '/v1/identity/civic-vote-proof',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { subjectUri, subjectType: 'cabildeo' },
    })
    assert.equal(proof.statusCode, 200)

    const earn = await app.inject({
      method: 'POST',
      url: '/v1/karma/earn',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { actionType: 'civic_vote_cast', detail: { subjectUri } },
    })
    assert.equal(earn.statusCode, 200)
    assert.equal(JSON.parse(earn.payload).points, 2)

    const me = await app.inject({
      method: 'GET',
      url: '/v1/karma/me',
      headers: { authorization: `Bearer ${accessToken}` },
    })
    const karma = JSON.parse(me.payload)
    assert.equal(karma.global, 12) // 10 (INE) + 2 (vote)
    assert.equal(karma.actions.ine_credential_issued, 10)
    assert.equal(karma.actions.civic_vote_cast, 2)
  })
})
