import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'
import { issueIneCredentialWithClientProof } from '../helpers/clientProof.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-zkp-test-'))
process.env.DATABASE_PATH = join(tmpDir, 'zkp-test.db')

describe('ZKP age proof integration', () => {
  let app: TestApp
  let accessToken: string

  before(async () => {
    const { buildApp } = await import('../../src/index.js')
    app = await buildApp()
    const start = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'zkpuser.bsky.social' },
    })
    const body = JSON.parse(start.payload)
    accessToken = body.tokens.accessToken
  })

  after(async () => {
    await app.close()
  })

  it('POST /v1/identity/ine/zkp-verify accepts a valid client-generated proof', async () => {
    const credential = await issueIneCredentialWithClientProof({
      app,
      accessToken,
      inePhotoBase64: 'mock-zkp-valid',
      selfieBase64: 'mock-selfie-valid',
      salt: 101001,
    })

    const res = await app.inject({
      method: 'POST',
      url: '/v1/identity/ine/zkp-verify',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: credential.clientProof.ageProofs.over18,
    })

    assert.equal(res.statusCode, 200)
    const body = JSON.parse(res.payload)
    assert.equal(body.valid, true)
    assert.equal(body.commitment, credential.body.commitment)
  })

  it('rejects a proof with tampered public signals', async () => {
    const { generateAgeProof } = await import('../../src/services/zkpService.js')
    const { proof, publicSignals } = await generateAgeProof({
      birthYear: 1990,
      salt: 555666,
      currentYear: 2026,
      ageThreshold: 18,
    })

    const tamperedSignals = [...publicSignals]
    tamperedSignals[0] = '12345678901234567890123456789012345678901234567890'

    const res = await app.inject({
      method: 'POST',
      url: '/v1/identity/ine/zkp-verify',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { proof, publicSignals: tamperedSignals },
    })

    assert.equal(res.statusCode, 400)
    const body = JSON.parse(res.payload)
    assert.equal(body.valid, false)
  })

  it('rejects a proof for a revoked credential', async () => {
    const credential = await issueIneCredentialWithClientProof({
      app,
      accessToken,
      inePhotoBase64: 'mock-zkp-revoke',
      selfieBase64: 'mock-selfie-revoke',
      salt: 202002,
    })

    const revokeRes = await app.inject({
      method: 'POST',
      url: '/v1/identity/revoke',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { revocationHash: credential.body.credential.revocationHash, reason: 'Test revocation' },
    })
    assert.equal(revokeRes.statusCode, 200)

    const res = await app.inject({
      method: 'POST',
      url: '/v1/identity/ine/zkp-verify',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: credential.clientProof.ageProofs.over18,
    })

    assert.equal(res.statusCode, 400)
    const body = JSON.parse(res.payload)
    assert.equal(body.valid, false)
    assert.equal(body.reason, 'credential_revoked')
  })

  it('GET /v1/identity/crl returns revoked hashes', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/identity/crl',
    })

    assert.equal(res.statusCode, 200)
    const body = JSON.parse(res.payload)
    assert.ok(Array.isArray(body.revokedHashes))
    assert.ok(body.revokedHashes.length >= 1)
    assert.ok(body.updatedAt)
  })
})
