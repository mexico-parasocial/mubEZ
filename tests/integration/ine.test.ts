import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'
import { buildAgeProofs, issueIneCredentialWithClientProof } from '../helpers/clientProof.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-test-'))
process.env.DATABASE_PATH = join(tmpDir, 'ine-test.db')

describe('INE verification integration', () => {
  let app: TestApp
  let accessToken: string
  let getDb: typeof import('../../src/db/connection.js').getDb

  before(async () => {
    const { buildApp } = await import('../../src/index.js')
    ;({ getDb } = await import('../../src/db/connection.js'))
    app = await buildApp()
    const start = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'ineuser.bsky.social' },
    })
    const body = JSON.parse(start.payload)
    accessToken = body.tokens.accessToken
  })

  after(async () => {
    await app.close()
  })

  it('POST /v1/identity/ine/analyze extracts INE data', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/identity/ine/analyze',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { inePhotoBase64: 'mock-ine-photo-123', simulatedMode: true },
    })

    assert.equal(res.statusCode, 200)
    const body = JSON.parse(res.payload)
    assert.ok(body.extracted)
    assert.ok(body.extracted.fullName)
    assert.ok(body.extracted.curp)
    assert.ok(body.extracted.curp.length >= 18)
    assert.ok(body.extracted.voterId)
    assert.ok(body.extracted.birthDate)
    assert.ok(['M', 'F'].includes(body.extracted.gender))
    assert.ok(body.extracted.address)
    assert.ok(body.extracted.address.state)
    assert.ok(body.ocrConfidence >= 0.9 && body.ocrConfidence <= 1.0)
    assert.equal(body.extractionStatus, 'complete')
  })

  it('POST /v1/identity/ine/verify performs face match and RENAPO', async () => {
    const analyze = await app.inject({
      method: 'POST',
      url: '/v1/identity/ine/analyze',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { inePhotoBase64: 'mock-ine-photo-456', simulatedMode: true },
    })
    const { extracted } = JSON.parse(analyze.payload)

    const res = await app.inject({
      method: 'POST',
      url: '/v1/identity/ine/verify',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { extracted, selfieBase64: 'mock-selfie-456', consentToStore: true },
    })

    assert.equal(res.statusCode, 200)
    const body = JSON.parse(res.payload)
    assert.ok(typeof body.faceMatch.score === 'number')
    assert.ok(body.faceMatch.score >= 0 && body.faceMatch.score <= 1)
    assert.ok(typeof body.faceMatch.passed === 'boolean')
    assert.ok(['active', 'deceased', 'not-found', 'duplicate'].includes(body.renapo.status))
    assert.equal(body.renapo.citizenship, 'MX')
    assert.ok(['verified', 'rejected', 'manual-review-required'].includes(body.overall))
    assert.ok(body.verificationId)
    assert.ok(body.verifiedAt)
  })

  it('POST /v1/identity/ine/credential issues a signed credential', async () => {
    const analyze = await app.inject({
      method: 'POST',
      url: '/v1/identity/ine/analyze',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { inePhotoBase64: 'mock-ine-photo-789', simulatedMode: true },
    })
    const { extracted } = JSON.parse(analyze.payload)

    const verify = await app.inject({
      method: 'POST',
      url: '/v1/identity/ine/verify',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { extracted, selfieBase64: 'mock-selfie-789', consentToStore: true },
    })
    const verification = JSON.parse(verify.payload)

    const clientProof = await buildAgeProofs({ birthDate: extracted.birthDate, salt: 789123n, over21: false })
    const res = await app.inject({
      method: 'POST',
      url: '/v1/identity/ine/credential',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { extracted, verification, ageProofs: clientProof.ageProofs },
    })

    assert.equal(res.statusCode, 200)
    const body = JSON.parse(res.payload)
    assert.ok(body.credential)
    assert.ok(body.credential.signature)
    assert.ok(body.credential.issuerKeyId)
    assert.equal(body.credential.claims.citizenship, 'MX')
    assert.equal(body.credential.claims.age_over_18, true)
    assert.equal(body.credential.claims.age_over_21, false)
    assert.ok(body.credential.claims.district_hash.startsWith('sha256:'))
    assert.ok(body.credential.claims.curp_hash.startsWith('sha256:'))
    assert.ok(body.credential.issuedAt)
    assert.ok(body.credential.expiresAt)
    assert.ok(body.proofArtifactId)
    assert.ok(body.verificationId)
    assert.equal(Object.hasOwn(body, 'salt'), false)
    assert.equal(Object.hasOwn(body, 'birthYear'), false)
    assert.equal(Object.hasOwn(body, 'revocationHash'), false)
    assert.equal(body.commitment, clientProof.commitment)

    const ledger = getDb()
      .prepare("SELECT detail_json FROM ledger WHERE target_id = ? AND target_type = 'identity' ORDER BY created_at DESC LIMIT 1")
      .get(body.proofArtifactId) as { detail_json: string } | undefined
    assert.ok(ledger)
    const detail = JSON.parse(ledger.detail_json)
    assert.equal(detail.credentialId, body.credential.id)
    assert.equal(detail.issuerKeyId, body.credential.issuerKeyId)
    assert.equal(detail.issuerDid, body.credential.issuerDid)
  })

  it('rejects invalid credential age proofs and duplicate commitments', async () => {
    const first = await issueIneCredentialWithClientProof({
      app,
      accessToken,
      inePhotoBase64: 'mock-ine-proof-invalid',
      selfieBase64: 'mock-selfie-proof-invalid',
      salt: 911222n,
    })
    assert.equal(first.response.statusCode, 200)

    const duplicate = await app.inject({
      method: 'POST',
      url: '/v1/identity/ine/credential',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        extracted: first.extracted,
        verification: first.verification,
        ageProofs: first.clientProof.ageProofs,
      },
    })
    assert.equal(duplicate.statusCode, 409)
    assert.equal(JSON.parse(duplicate.payload).code, 'COMMITMENT_ALREADY_REGISTERED')

    const tamperedSignals = [...first.clientProof.ageProofs.over18.publicSignals]
    tamperedSignals[0] = '12345678901234567890'
    const invalid = await app.inject({
      method: 'POST',
      url: '/v1/identity/ine/credential',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        extracted: first.extracted,
        verification: first.verification,
        ageProofs: {
          over18: { proof: first.clientProof.ageProofs.over18.proof, publicSignals: tamperedSignals },
        },
      },
    })
    assert.equal(invalid.statusCode, 400)
    assert.equal(JSON.parse(invalid.payload).code, 'invalid_proof')
  })

})
