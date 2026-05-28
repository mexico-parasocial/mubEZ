import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'
import { issueIneCredentialWithClientProof } from '../helpers/clientProof.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-nullifier-test-'))
process.env.DATABASE_PATH = join(tmpDir, 'nullifier-test.db')

describe('Nullifier ZKP integration', () => {
  let app: TestApp
  let accessToken: string

  before(async () => {
    const { buildApp } = await import('../../src/index.js')
    app = await buildApp()
    const start = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'nullifieruser.bsky.social' },
    })
    const body = JSON.parse(start.payload)
    accessToken = body.tokens.accessToken
  })

  after(async () => {
    await app.close()
  })

  it('POST /v1/identity/ine/zkp-nullifier accepts a valid nullifier proof', async () => {
    const credential = await issueIneCredentialWithClientProof({
      app,
      accessToken,
      inePhotoBase64: 'mock-nullifier-valid',
      selfieBase64: 'mock-selfie-valid',
      salt: 303003,
    })

    const { generateNullifierProof } = await import('../../src/services/zkpService.js')
    const { proof, publicSignals, nullifier } = await generateNullifierProof({
      birthYear: credential.clientProof.witness.birthYear,
      salt: credential.clientProof.witness.salt,
      communityId: 42,
      currentYear: new Date().getFullYear(),
      ageThreshold: 18,
    })

    const res = await app.inject({
      method: 'POST',
      url: '/v1/identity/ine/zkp-nullifier',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { proof, publicSignals, communityId: '42' },
    })

    assert.equal(res.statusCode, 200)
    const body = JSON.parse(res.payload)
    assert.equal(body.valid, true)
    assert.equal(body.commitment, credential.body.commitment)
    assert.equal(body.nullifier, nullifier)
  })

  it('rejects a reused nullifier for the same community', async () => {
    const credential = await issueIneCredentialWithClientProof({
      app,
      accessToken,
      inePhotoBase64: 'mock-nullifier-reuse',
      selfieBase64: 'mock-selfie-reuse',
      salt: 404004,
    })

    const { generateNullifierProof } = await import('../../src/services/zkpService.js')
    const { proof, publicSignals } = await generateNullifierProof({
      birthYear: credential.clientProof.witness.birthYear,
      salt: credential.clientProof.witness.salt,
      communityId: 99,
      currentYear: new Date().getFullYear(),
      ageThreshold: 18,
    })

    const first = await app.inject({
      method: 'POST',
      url: '/v1/identity/ine/zkp-nullifier',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { proof, publicSignals, communityId: '99' },
    })
    assert.equal(first.statusCode, 200)

    // Try to reuse the same nullifier
    const second = await app.inject({
      method: 'POST',
      url: '/v1/identity/ine/zkp-nullifier',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { proof, publicSignals, communityId: '99' },
    })

    assert.equal(second.statusCode, 400)
    const body = JSON.parse(second.payload)
    assert.equal(body.valid, false)
    assert.equal(body.reason, 'nullifier_already_used')
  })

  it('rejects a nullifier proof with community mismatch', async () => {
    const credential = await issueIneCredentialWithClientProof({
      app,
      accessToken,
      inePhotoBase64: 'mock-nullifier-mismatch',
      selfieBase64: 'mock-selfie-mismatch',
      salt: 505005,
    })

    const { generateNullifierProof } = await import('../../src/services/zkpService.js')
    const { proof, publicSignals } = await generateNullifierProof({
      birthYear: credential.clientProof.witness.birthYear,
      salt: credential.clientProof.witness.salt,
      communityId: 7,
      currentYear: new Date().getFullYear(),
      ageThreshold: 18,
    })

    // Submit with wrong communityId
    const res = await app.inject({
      method: 'POST',
      url: '/v1/identity/ine/zkp-nullifier',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { proof, publicSignals, communityId: '99' },
    })

    assert.equal(res.statusCode, 400)
    const body = JSON.parse(res.payload)
    assert.equal(body.valid, false)
    assert.equal(body.reason, 'community_mismatch')
  })
})
