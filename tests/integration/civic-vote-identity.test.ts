import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'
import { issueIneCredentialWithClientProof } from '../helpers/clientProof.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-civic-vote-test-'))
process.env.DATABASE_PATH = join(tmpDir, 'civic-vote-test.db')

describe('civic vote identity integration', () => {
  let app: TestApp
  let accessToken: string

  before(async () => {
    const { buildApp } = await import('../../src/index.js')
    app = await buildApp()
    const start = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'civic-voter.bsky.social' },
    })
    const body = JSON.parse(start.payload)
    accessToken = body.tokens.accessToken

    // Vote nullifiers require proof-of-humanity: bind an INE credential.
    const credential = await issueIneCredentialWithClientProof({
      app,
      accessToken,
      inePhotoBase64: 'mock-civic-vote-ine',
      selfieBase64: 'mock-civic-vote-selfie',
    })
    assert.equal(credential.response.statusCode, 200)
  })

  after(async () => {
    await app.close()
  })

  it('rejects vote proof issuance without an INE commitment', async () => {
    const start = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'unverified-voter.bsky.social' },
    })
    const unverifiedToken = JSON.parse(start.payload).tokens.accessToken

    const res = await app.inject({
      method: 'POST',
      url: '/v1/identity/civic-vote-proof',
      headers: { authorization: `Bearer ${unverifiedToken}` },
      payload: {
        subjectUri: 'at://did:plc:example/com.para.civic.cabildeo/abc',
        subjectType: 'cabildeo',
      },
    })

    assert.equal(res.statusCode, 403)
    const body = JSON.parse(res.payload)
    assert.equal(body.code, 'INE_COMMITMENT_REQUIRED')
  })

  it('issues a stable vote nullifier per person and subject', async () => {
    const payload = {
      subjectUri: 'at://did:plc:example/com.para.civic.cabildeo/abc',
      subjectType: 'cabildeo',
    }
    const first = await app.inject({
      method: 'POST',
      url: '/v1/identity/civic-vote-proof',
      headers: { authorization: `Bearer ${accessToken}` },
      payload,
    })
    const second = await app.inject({
      method: 'POST',
      url: '/v1/identity/civic-vote-proof',
      headers: { authorization: `Bearer ${accessToken}` },
      payload,
    })

    assert.equal(first.statusCode, 200)
    assert.equal(second.statusCode, 200)
    const firstProof = JSON.parse(first.payload).proof
    const secondProof = JSON.parse(second.payload).proof
    assert.equal(firstProof.voteNullifier, secondProof.voteNullifier)
    assert.equal(firstProof.eligibilityProofRef, secondProof.eligibilityProofRef)
    assert.equal(firstProof.subjectType, 'cabildeo')
  })

  it('gives the same human the same nullifier from a second session', async () => {
    /*
     * The regression this exists for: person roots used to be filed under the
     * session, and the only guard deduplicated on a commitment whose salt the
     * client picks. Re-enrolling therefore minted a second person who could
     * vote again on the same subject. Same INE photo means same CURP, so both
     * sessions must land on one person root.
     */
    const subjectUri = 'at://did:plc:example/com.para.civic.cabildeo/two-devices'

    const first = await app.inject({
      method: 'POST',
      url: '/v1/identity/civic-vote-proof',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { subjectUri, subjectType: 'cabildeo' },
    })
    assert.equal(first.statusCode, 200)

    const secondSession = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'civic-voter-second-device.bsky.social' },
    })
    const secondToken = JSON.parse(secondSession.payload).tokens.accessToken

    const credential = await issueIneCredentialWithClientProof({
      app,
      accessToken: secondToken,
      inePhotoBase64: 'mock-civic-vote-ine',
      selfieBase64: 'mock-civic-vote-selfie',
    })
    assert.equal(credential.response.statusCode, 200)

    const second = await app.inject({
      method: 'POST',
      url: '/v1/identity/civic-vote-proof',
      headers: { authorization: `Bearer ${secondToken}` },
      payload: { subjectUri, subjectType: 'cabildeo' },
    })
    assert.equal(second.statusCode, 200)

    assert.equal(
      JSON.parse(second.payload).proof.voteNullifier,
      JSON.parse(first.payload).proof.voteNullifier,
    )
  })

  it('issues a proof that carries no DID, linked pseudoidentity or not', async () => {
    const alias = await app.inject({
      method: 'POST',
      url: '/v1/identity/civic-vote-aliases',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { did: 'did:plc:pseudoalias', handle: 'pseudo.example' },
    })
    assert.equal(alias.statusCode, 200)
    // The caller is told about the alias it linked and nothing else: returning
    // every alias of the person handed out the correlation between them.
    assert.equal(JSON.parse(alias.payload).alias.aliasDids, undefined)

    const proof = await app.inject({
      method: 'POST',
      url: '/v1/identity/civic-vote-proof',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        subjectUri: 'at://did:plc:example/com.para.civic.cabildeo/shared',
        subjectType: 'cabildeo',
      },
    })

    assert.equal(proof.statusCode, 200)
    const body = JSON.parse(proof.payload).proof
    // CD-12: the nullifier is derived from the person root alone, so no DID
    // enters the request or the response on this path.
    assert.equal(body.aliasDid, undefined)
    assert.equal(body.aliasDids, undefined)
    assert.match(body.voteNullifier, /^[a-f0-9]{64}$/)
  })

  it('refuses a request that tries to name an alias', async () => {
    const proof = await app.inject({
      method: 'POST',
      url: '/v1/identity/civic-vote-proof',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        subjectUri: 'at://did:plc:example/com.para.civic.cabildeo/strict',
        subjectType: 'cabildeo',
        aliasDid: 'did:plc:pseudoalias',
      },
    })

    assert.equal(proof.statusCode, 422)
  })
})
