import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'
import { issueIneCredentialWithClientProof } from '../helpers/clientProof.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-civic-vote-test-'))
process.env.CIVIC_VOTE_PROOF_SECRET = 'test-only-civic-authorization-secret-2026'
process.env.CIVIC_DELEGATION_RESOLVER_SECRET = 'test-only-civic-delegation-resolver-secret-2026'
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
        subjectType: 'cabildeo', selectedOption: 1,
      },
    })

    assert.equal(res.statusCode, 403)
    const body = JSON.parse(res.payload)
    assert.equal(body.code, 'INE_COMMITMENT_REQUIRED')
  })

  it('requires the chosen option when authorizing a public cabildeo vote', async () => {
    const response = await app.inject({
      method: 'POST', url: '/v1/identity/civic-vote-proof',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { subjectUri: 'at://did:plc:example/com.para.civic.cabildeo/missing-option', subjectType: 'cabildeo' },
    })
    assert.equal(response.statusCode, 400)
    assert.equal(JSON.parse(response.payload).code, 'INVALID_OPTION')
  })

  it('issues a stable vote nullifier per person and subject', async () => {
    const payload = {
      subjectUri: 'at://did:plc:example/com.para.civic.cabildeo/abc',
      subjectType: 'cabildeo', selectedOption: 1,
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
      payload: { subjectUri, subjectType: 'cabildeo', selectedOption: 1 },
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
      payload: { subjectUri, subjectType: 'cabildeo', selectedOption: 1 },
    })
    assert.equal(second.statusCode, 200)

    assert.equal(
      JSON.parse(second.payload).proof.voteNullifier,
      JSON.parse(first.payload).proof.voteNullifier,
    )
    assert.notEqual(
      JSON.parse(second.payload).proof.eligibilityProofRef,
      JSON.parse(first.payload).proof.eligibilityProofRef,
    )
  })

  it('binds a delegation to its author, delegate, scope and direct-vote person', async () => {
    const subjectUri = 'at://did:plc:example/com.para.civic.cabildeo/delegated'
    const session = await app.inject({ method: 'GET', url: '/v1/sessions/me',
      headers: { authorization: `Bearer ${accessToken}` } })
    const actorDid = JSON.parse(session.payload).session.did
    const claim = { mode: 'active', delegateTo: 'did:plc:chosen-delegate', cabildeo: subjectUri }
    const issued = await app.inject({ method: 'POST', url: '/v1/identity/civic-delegation-proof',
      headers: { authorization: `Bearer ${accessToken}` }, payload: claim })
    assert.equal(issued.statusCode, 200)
    const eligibilityProofRef = JSON.parse(issued.payload).proof.eligibilityProofRef
    const verify = (payload: unknown, resolver = false) => app.inject({ method: 'POST',
      url: '/v1/identity/civic-delegation-proof/verify',
      headers: resolver ? { 'x-m8-resolver-secret': process.env.CIVIC_DELEGATION_RESOLVER_SECRET! } : {},
      payload })
    const publicClaim = { ...claim, actorDid, eligibilityProofRef }
    assert.equal((await verify(publicClaim)).statusCode, 204)
    for (const changed of [
      { actorDid: 'did:plc:other' }, { delegateTo: 'did:plc:other' },
      { cabildeo: subjectUri + '-other' }, { eligibilityProofRef: 'invented' },
    ]) assert.equal((await verify({ ...publicClaim, ...changed })).statusCode, 422)
    assert.equal((await verify({ ...publicClaim, subjectUri })).statusCode, 403)
    const resolved = await verify({ ...publicClaim, subjectUri }, true)
    assert.equal(resolved.statusCode, 200)
    const direct = await app.inject({ method: 'POST', url: '/v1/identity/civic-vote-proof',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { subjectUri, subjectType: 'cabildeo', selectedOption: 0 } })
    assert.equal(JSON.parse(resolved.payload).voteNullifier,
      JSON.parse(direct.payload).proof.voteNullifier)
  })

  it('binds a passive delegation to its named delegate and all three filters', async () => {
    const session = await app.inject({ method: 'GET', url: '/v1/sessions/me',
      headers: { authorization: `Bearer ${accessToken}` } })
    const actorDid = JSON.parse(session.payload).session.did
    const claim = { mode: 'passive', delegateTo: 'did:plc:delegate',
      party: 'Example', community: 'community-one', scopeFlairs: ['education'] }
    const issued = await app.inject({ method: 'POST', url: '/v1/identity/civic-delegation-proof',
      headers: { authorization: `Bearer ${accessToken}` }, payload: claim })
    assert.equal(issued.statusCode, 200)
    const eligibilityProofRef = JSON.parse(issued.payload).proof.eligibilityProofRef
    const verify = (payload: unknown) => app.inject({ method: 'POST',
      url: '/v1/identity/civic-delegation-proof/verify', payload })
    const publicClaim = { ...claim, actorDid, eligibilityProofRef }
    assert.equal((await verify(publicClaim)).statusCode, 204)
    for (const changed of [
      {delegateTo: 'did:plc:other'}, {party: 'Other'},
      {community: 'other-community'}, {scopeFlairs: ['housing']},
    ]) assert.equal((await verify({...publicClaim, ...changed})).statusCode, 422)
  })

  it('removes the unused alias endpoint and returns no identity linkage', async () => {
    const alias = await app.inject({
      method: 'POST',
      url: '/v1/identity/civic-vote-aliases',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { did: 'did:plc:pseudoalias', handle: 'pseudo.example' },
    })
    assert.equal(alias.statusCode, 404)

    const proof = await app.inject({
      method: 'POST',
      url: '/v1/identity/civic-vote-proof',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        subjectUri: 'at://did:plc:example/com.para.civic.cabildeo/shared',
        subjectType: 'cabildeo', selectedOption: 1,
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
        subjectType: 'cabildeo', selectedOption: 1,
        aliasDid: 'did:plc:pseudoalias',
      },
    })

    assert.equal(proof.statusCode, 422)
  })
  it('verifies a bound authorization and refuses copied or altered claims', async () => {
    const subjectUri = 'at://did:plc:example/com.para.civic.cabildeo/verify'
    const issued = await app.inject({
      method: 'POST', url: '/v1/identity/civic-vote-proof',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { subjectUri, subjectType: 'cabildeo', selectedOption: 1 },
    })
    assert.equal(issued.statusCode, 200)
    const { proof } = JSON.parse(issued.payload)
    const sessionResponse = await app.inject({
      method: 'GET', url: '/v1/sessions/me',
      headers: { authorization: `Bearer ${accessToken}` },
    })
    const actorDid = JSON.parse(sessionResponse.payload).session.did
    const claim = { actorDid, subjectUri, selectedOption: 1,
      voteNullifier: proof.voteNullifier, eligibilityProofRef: proof.eligibilityProofRef }
    const verify = (payload: unknown) => app.inject({
      method: 'POST', url: '/v1/identity/civic-vote-proof/verify', payload,
    })
    assert.equal((await verify(claim)).statusCode, 204)
    for (const change of [
      { actorDid: 'did:plc:attacker' }, { selectedOption: 2 },
      { subjectUri: subjectUri + '-other' }, { voteNullifier: 'a'.repeat(64) },
      { eligibilityProofRef: 'm8:cabildeo:v1:' + 'a'.repeat(43) },
      { eligibilityProofRef: 'invented' },
    ]) {
      assert.equal((await verify({ ...claim, ...change })).statusCode, 422)
    }
    const { getDb } = await import('../../src/db/connection.js')
    const db = getDb()
    assert.equal(db.prepare("SELECT name FROM sqlite_master WHERE name = 'person_aliases'").get(), undefined)
    assert.equal(db.prepare("SELECT count(*) FROM ledger WHERE action = 'CivicVoteProofIssued'").pluck().get(), 0)
    db.prepare("UPDATE person_roots SET status = 'revoked' WHERE id = (SELECT person_id FROM civic_vote_nullifiers WHERE vote_nullifier = ?)").run(proof.voteNullifier)
    assert.equal((await verify(claim)).statusCode, 422)
  })

})
