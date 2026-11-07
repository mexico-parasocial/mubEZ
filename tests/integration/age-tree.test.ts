import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, sign } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'
import { createHolderBinding } from '../helpers/clientProof.js'

/*
 * CD-16 over HTTP: the issuer attests age from the INE birth date, and
 * publishes the v3 age tree. Every check here runs before the Groth16 proofs
 * are verified, so none of it needs the compiled circuit artifacts.
 */

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-age-tree-http-'))
process.env.DATABASE_PATH = join(tmpDir, 'age-tree-http.db')
const issuerKeys = generateKeyPairSync('ed25519')
process.env.IDENTITY_ISSUER_DID = 'did:m8:ine:age-tree-http'
process.env.IDENTITY_ISSUER_KEY_ID = 'ine-ed25519-age-tree'
process.env.IDENTITY_ISSUER_PRIVATE_JWK = JSON.stringify(issuerKeys.privateKey.export({ format: 'jwk' }))
process.env.IDENTITY_ISSUER_PUBLIC_JWK = JSON.stringify(issuerKeys.publicKey.export({ format: 'jwk' }))
for (const key of ['IDENTITY_ISSUER_PREVIOUS_PUBLIC_JWK', 'IDENTITY_ISSUER_PREVIOUS_KEY_ID', 'IDENTITY_ISSUER_PREVIOUS_KEY_EXPIRES_AT', 'IDENTITY_ISSUER_REVOKED_KEY_IDS']) {
  delete process.env[key]
}
process.env.RATE_LIMIT_AUTH_MAX = '1000'
process.env.GROWTHBOOK_FEATURE_OVERRIDES = JSON.stringify({
  'm8:auth:dev_token_bootstrap': true,
  'm8:demo_identity_wallet:enable': false,
  'm8:simulated_ine:enable': true,
})

/** Never verified: every request below is refused before the proofs are checked. */
const UNCHECKED_PROOF = { proof: {}, publicSignals: ['1', String(new Date().getFullYear()), '18'] }

describe('issuer-bound age and the age tree over HTTP (CD-16)', () => {
  let app: TestApp
  let auth: Record<string, string>
  let sessionId: string
  let tree: typeof import('../../src/services/ageTree.js')
  let getDb: typeof import('../../src/db/connection.js').getDb

  const call = async (method: string, url: string, payload?: unknown, headers: Record<string, string> = auth) => {
    const res = await app.inject({ method, url, headers, payload })
    return { status: res.statusCode, body: res.payload ? JSON.parse(res.payload) : undefined }
  }
  const challenge = async () => (await call('GET', '/v1/sessions/me')).body.session.issuanceChallenge as string

  /** A simulated INE record with its birth date replaced. */
  async function ineRecord(birthDate: string) {
    const extracted = (await call('POST', '/v1/identity/ine/analyze', { inePhotoBase64: `age-${birthDate}`, simulatedMode: true })).body.extracted
    extracted.birthDate = birthDate
    const verification = (await call('POST', '/v1/identity/ine/verify', { extracted, selfieBase64: 'selfie', consentToStore: true })).body
    return { extracted, verification }
  }

  async function requestCredential(birthDate: string, extra: Record<string, unknown> = {}) {
    const issuanceChallenge = await challenge()
    const { holderPublicKey, holderKeyProof } = await createHolderBinding(issuanceChallenge)
    return call('POST', '/v1/identity/ine/credential', {
      ...(await ineRecord(birthDate)),
      issuanceChallenge,
      ageProofs: { over18: UNCHECKED_PROOF },
      holderPublicKey,
      holderKeyProof,
      ...extra,
    })
  }

  /** YYYY-MM-DD, `years` before today minus `days`. */
  function yearsAgo(years: number, days = 0) {
    const date = new Date()
    date.setUTCFullYear(date.getUTCFullYear() - years)
    date.setUTCDate(date.getUTCDate() - days)
    return date.toISOString().slice(0, 10)
  }

  async function issuerKeyPem(keyId: string) {
    const issuers = (await call('GET', '/v1/issuers', undefined, {})).body as Array<{ keyId: string; publicKeyPem: string }>
    return issuers.find((issuer) => issuer.keyId === keyId)!.publicKeyPem
  }

  before(async () => {
    const { buildApp } = await import('../../src/index.js')
    const wallet = await import('../../src/services/identityWallet.js')
    wallet.resetSharedIssuerKeyStore()
    tree = await import('../../src/services/ageTree.js')
    ;({ getDb } = await import('../../src/db/connection.js'))
    app = await buildApp()
    const start = await app.inject({ method: 'POST', url: '/v1/sessions/start', payload: { identifier: 'ageholder.bsky.social' } })
    auth = { authorization: `Bearer ${JSON.parse(start.payload).tokens.accessToken}` }
    sessionId = (getDb().prepare("SELECT session_id FROM sessions WHERE handle = 'ageholder.bsky.social' AND status = 'active'").get() as { session_id: string }).session_id
  })

  after(async () => {
    await app.close()
  })

  describe('age attested from the INE birth date', () => {
    it('refuses an INE record under 18, whatever the client proves', async () => {
      const res = await requestCredential(yearsAgo(17))
      assert.equal(res.status, 403)
      assert.equal(res.body.code, 'AGE_NOT_ATTESTED')
    })

    it('counts to the day: the day before the 18th birthday is still 17', async () => {
      // Two days of margin for the issuer's time zone, which may still be on yesterday.
      const res = await requestCredential(yearsAgo(18, -2))
      assert.equal(res.body.code, 'AGE_NOT_ATTESTED')
    })

    it('refuses a record whose birth date is not a real date', async () => {
      for (const birthDate of ['2001-02-29', 'not-a-date', yearsAgo(-1)]) {
        const res = await requestCredential(birthDate)
        assert.equal(res.status, 400, birthDate)
        assert.equal(res.body.code, 'BIRTH_DATE_INVALID', birthDate)
      }
    })

    it('refuses an over-21 proof the birth date does not support', async () => {
      const res = await requestCredential(yearsAgo(19), {
        ageProofs: { over18: UNCHECKED_PROOF, over21: { ...UNCHECKED_PROOF, publicSignals: ['1', String(new Date().getFullYear()), '21'] } },
      })
      assert.equal(res.status, 400)
      assert.equal(res.body.code, 'AGE_CLAIM_MISMATCH')
    })

    it('lets an adult record through to the proof check', async () => {
      const res = await requestCredential(yearsAgo(30))
      assert.equal(res.status, 400)
      assert.equal(res.body.code, 'invalid_proof', 'the age check passed; the dummy proof is what fails')
    })

    it('rejects a malformed age leaf commitment without burning the challenge', async () => {
      for (const ageLeafCommitment of ['0', '01', 'abc', tree.parseLeafCommitment.name]) {
        const before = await challenge()
        const res = await requestCredential(yearsAgo(30), { ageLeafCommitment })
        assert.equal(res.status, 400, ageLeafCommitment)
        assert.equal(res.body.code, 'AGE_LEAF_COMMITMENT_INVALID', ageLeafCommitment)
        assert.equal(await challenge(), before)
      }
    })
  })

  describe('age leaf commitments through the wallet relay', () => {
    it('takes H from the wallet\'s binding, never from PARA', async () => {
      const binding = (await call('POST', '/v1/identity/wallet/binding-requests')).body
      const key = generateKeyPairSync('ed25519')
      const { holderBindingMessage } = await import('../../src/services/identityWallet.js')
      const proof = sign(null, Buffer.from(holderBindingMessage(binding.issuanceChallenge)), key.privateKey).toString('base64url')
      const holderPublicKey = key.publicKey.export({ type: 'spki', format: 'pem' }).toString()

      const malformed = await call('POST', `/v1/identity/wallet/binding-requests/${binding.id}/fulfill`, {
        holderPublicKey, holderKeyProof: proof, ageLeafCommitment: '0',
      })
      assert.equal(malformed.status, 400)
      assert.equal(malformed.body.code, 'AGE_LEAF_COMMITMENT_INVALID')

      const bound = await call('POST', `/v1/identity/wallet/binding-requests/${binding.id}/fulfill`, {
        holderPublicKey, holderKeyProof: proof, ageLeafCommitment: '123456789',
      })
      assert.equal(bound.status, 200)
      const row = getDb().prepare('SELECT age_leaf_commitment FROM wallet_binding_requests WHERE id = ?').get(binding.id) as { age_leaf_commitment: string }
      assert.equal(row.age_leaf_commitment, '123456789')

      const before = await challenge()
      const fromPara = await call('POST', '/v1/identity/ine/credential', {
        ...(await ineRecord(yearsAgo(30))),
        issuanceChallenge: binding.issuanceChallenge,
        ageProofs: { over18: UNCHECKED_PROOF },
        walletBindingRequestId: binding.id,
        ageLeafCommitment: '987654321',
      })
      assert.equal(fromPara.status, 400)
      assert.equal(fromPara.body.code, 'AGE_LEAF_COMMITMENT_FROM_WALLET')
      assert.equal(await challenge(), before)
    })
  })

  describe('the published tree', () => {
    const H = 424242424242n
    const BIRTH_DAY = 36_000
    let enrollmentId: string
    let leaf: import('../../src/services/ageTree.js').IssuedAgeLeaf

    before(async () => {
      enrollmentId = 'proof-ine-age-tree-http'
      const now = new Date().toISOString()
      getDb().prepare(`
        INSERT INTO grants (id, session_id, app_id, app_name, app_kind, surface, requested_claims_json, proof_mode, status, reason, requested_at)
        VALUES ('grant-age-tree-http', ?, 'para.identity', 'PARA Identity', 'Verifier', 'civic', '[]', 'proof-only', 'approved', 'test', ?)
      `).run(sessionId, now)
      getDb().prepare(`
        INSERT INTO proof_artifacts
          (id, session_id, grant_id, request_id, claim_type, outcome, statement, audience_app_id, audience_app_name, surface, status, issued_at, expires_at, revocation_hash, commitment)
        VALUES (?, ?, 'grant-age-tree-http', 'ine-verification', 'has_para_verification', 'verified', 'test', 'para.identity', 'PARA Identity', 'civic', 'active', ?, ?, 'rev-age-tree-http', '777')
      `).run(enrollmentId, sessionId, now, new Date(Date.now() + 365 * 86_400_000).toISOString())
      leaf = await tree.appendAgeLeaf({ proofArtifactId: enrollmentId, leafCommitment: H, birthDay: BIRTH_DAY, enrollmentExpiresAt: null })
    })

    it('serves a signed root anyone can check against /v1/issuers, without a session', async () => {
      const res = await call('GET', '/v1/identity/age-tree/root', undefined, {})
      assert.equal(res.status, 200)
      assert.equal(res.body.alg, 'm8.identity.ageTree.root.v1')
      assert.equal(res.body.depth, 20)
      assert.equal(res.body.root, leaf.root.root)
      assert.ok(tree.verifyAgeTreeRootSignature(res.body, await issuerKeyPem(res.body.keyId)))

      const roots = await call('GET', '/v1/identity/age-tree/roots', undefined, {})
      assert.equal(roots.status, 200)
      assert.equal(roots.body.windowSeconds, 86_400)
      assert.equal(roots.body.roots[0].root, leaf.root.root)
      assert.equal(roots.body.roots[0].supersededAt, null)
    })

    it('serves chunks and chunk roots a wallet can rebuild its path from', async () => {
      const chunk = await call('GET', '/v1/identity/age-tree/chunks/0', undefined, {})
      const tops = await call('GET', '/v1/identity/age-tree/chunk-roots', undefined, {})
      assert.equal(chunk.status, 200)
      assert.equal(tops.status, 200)
      assert.equal(chunk.body.leaves[leaf.leafIndex], (await tree.computeAgeLeaf(H, BIRTH_DAY, leaf.expiryDay)).toString())
      const path = await tree.merklePathFromChunks(leaf.leafIndex, chunk.body.leaves, tops.body.nodes)
      assert.equal(path.root, leaf.root.root)
      assert.ok(await tree.verifyAgeTreeMerklePath(chunk.body.leaves[leaf.leafIndex], path))

      for (const bad of ['abc', '-1', '1024', '1.5']) {
        const res = await call('GET', `/v1/identity/age-tree/chunks/${bad}`, undefined, {})
        assert.equal(res.status, 400, bad)
        assert.equal(res.body.code, 'AGE_TREE_CHUNK_INVALID', bad)
      }
    })

    it('refreshes the leaf for its holder only', async () => {
      const payload = { leafIndex: leaf.leafIndex, leafCommitment: H.toString(), birthDay: BIRTH_DAY, expiryDay: leaf.expiryDay }
      assert.equal((await call('POST', '/v1/identity/age-tree/leaves/refresh', payload, {})).status, 401)

      const wrong = await call('POST', '/v1/identity/age-tree/leaves/refresh', { ...payload, birthDay: BIRTH_DAY + 1 })
      assert.equal(wrong.status, 403)
      assert.equal(wrong.body.code, 'AGE_LEAF_MISMATCH')

      const refreshed = await call('POST', '/v1/identity/age-tree/leaves/refresh', payload)
      assert.equal(refreshed.status, 200)
      assert.equal(refreshed.body.leafIndex, leaf.leafIndex + 1)
      assert.equal(refreshed.body.birthDay, BIRTH_DAY)
      assert.ok(tree.verifyAgeTreeRootSignature(refreshed.body.root, await issuerKeyPem(refreshed.body.root.keyId)))
      leaf = refreshed.body
    })

    it('zeroes the leaf when the holder revokes the enrollment, and keeps it out', async () => {
      const before = (await call('GET', '/v1/identity/age-tree/root', undefined, {})).body
      const revoked = await call('POST', '/v1/identity/revoke', { proofArtifactId: enrollmentId })
      assert.equal(revoked.status, 200)

      const after = (await call('GET', '/v1/identity/age-tree/root', undefined, {})).body
      assert.notEqual(after.root, before.root)
      const chunk = (await call('GET', '/v1/identity/age-tree/chunks/0', undefined, {})).body
      assert.equal(chunk.leaves[leaf.leafIndex], '0')

      const roots = (await call('GET', '/v1/identity/age-tree/roots', undefined, {})).body.roots as Array<{ root: string; supersededAt: string | null }>
      assert.ok(roots.find((root) => root.root === before.root)?.supersededAt, 'the old root stays acceptable for the window, marked superseded')

      const refresh = await call('POST', '/v1/identity/age-tree/leaves/refresh', {
        leafIndex: leaf.leafIndex, leafCommitment: H.toString(), birthDay: BIRTH_DAY, expiryDay: leaf.expiryDay,
      })
      assert.equal(refresh.status, 403)
      assert.equal(refresh.body.code, 'AGE_LEAF_ENROLLMENT_INACTIVE')
    })
  })
})
