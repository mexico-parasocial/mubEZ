import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'

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
  })

  after(async () => {
    await app.close()
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

  it('allows an explicitly linked pseudoidentity to request the same person nullifier', async () => {
    const alias = await app.inject({
      method: 'POST',
      url: '/v1/identity/civic-vote-aliases',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { did: 'did:plc:pseudoalias', handle: 'pseudo.example' },
    })
    assert.equal(alias.statusCode, 200)

    const proof = await app.inject({
      method: 'POST',
      url: '/v1/identity/civic-vote-proof',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        subjectUri: 'at://did:plc:example/com.para.civic.cabildeo/shared',
        subjectType: 'cabildeo',
        aliasDid: 'did:plc:pseudoalias',
      },
    })

    assert.equal(proof.statusCode, 200)
    const body = JSON.parse(proof.payload).proof
    assert.equal(body.aliasDid, 'did:plc:pseudoalias')
    assert.ok(body.aliasDids.includes('did:plc:pseudoalias'))
    assert.match(body.voteNullifier, /^[a-f0-9]{64}$/)
  })
})
