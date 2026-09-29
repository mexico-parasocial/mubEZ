import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, verify as verifySignature, type KeyObject } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'
import type { M8IdentityCredential, M8IdentityRequest } from '../../src/types/index.js'
import { issueIneCredentialWithClientProof } from '../helpers/clientProof.js'

/*
 * CD-13 end to end, production-like: a configured issuer key (never the demo
 * key), the demo wallet off so an unrecorded credential fails revocation
 * closed, and the holder signing on its own side. Simulated INE is the only
 * issuance route this codebase has; it stays off in production.
 */

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-wallet-v2-'))
process.env.DATABASE_PATH = join(tmpDir, 'wallet-v2.db')

const ISSUER_DID = 'did:m8:ine:v2-flow-issuer'
const ISSUER_KEY_ID = 'ine-ed25519-v2-flow'
const issuerKeys = generateKeyPairSync('ed25519')
process.env.IDENTITY_ISSUER_DID = ISSUER_DID
process.env.IDENTITY_ISSUER_KEY_ID = ISSUER_KEY_ID
process.env.IDENTITY_ISSUER_PRIVATE_JWK = JSON.stringify(issuerKeys.privateKey.export({ format: 'jwk' }))
process.env.IDENTITY_ISSUER_PUBLIC_JWK = JSON.stringify(issuerKeys.publicKey.export({ format: 'jwk' }))
for (const key of [
  'IDENTITY_ISSUER_PREVIOUS_PUBLIC_JWK',
  'IDENTITY_ISSUER_PREVIOUS_KEY_ID',
  'IDENTITY_ISSUER_PREVIOUS_KEY_EXPIRES_AT',
  'IDENTITY_ISSUER_REVOKED_KEY_IDS',
]) {
  delete process.env[key]
}
process.env.GROWTHBOOK_FEATURE_OVERRIDES = JSON.stringify({
  'm8:auth:dev_token_bootstrap': true,
  'm8:demo_identity_wallet:enable': false,
  'm8:simulated_ine:enable': true,
})

const ALL_ELEMENTS = ['age_over_18', 'age_over_21', 'citizenship', 'district_hash', 'curp_hash'] as const

function stableJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`
  return `{${Object.entries(value as Record<string, unknown>)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${JSON.stringify(k)}:${stableJson(v)}`)
    .join(',')}}`
}

describe('identity wallet v2: issuance → presentation → verification → replay → revocation', () => {
  let app: TestApp
  let auth: Record<string, string>
  let wallet: typeof import('../../src/services/identityWallet.js')
  let holderPrivateKey: KeyObject
  let credential: M8IdentityCredential
  let basicCredential: M8IdentityCredential
  let revocationHash: string

  async function newRequest(elements: readonly (typeof ALL_ELEMENTS)[number][], required: string[] = ['age_over_18']) {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/identity/request',
      headers: auth,
      payload: {
        audienceAppId: 'v2.flow.verifier',
        audienceAppName: 'V2 Flow Verifier',
        purpose: 'CD-13 end-to-end',
        requestedElements: elements.map((id) => ({
          id, intentToStore: { mode: 'will-not-store' }, required: required.includes(id),
        })),
      },
    })
    assert.equal(res.statusCode, 201)
    return JSON.parse(res.payload) as M8IdentityRequest
  }

  async function present(request: M8IdentityRequest, presented: M8IdentityCredential, disclosed: (typeof ALL_ELEMENTS)[number][], key = holderPrivateKey) {
    const presentation = wallet.signWalletPresentation({
      request, credential: presented, disclosedClaimIds: disclosed, holderPrivateKey: key,
    })
    const res = await app.inject({
      method: 'POST',
      url: '/v1/identity/verify',
      headers: auth,
      payload: { requestId: request.id, presentation },
    })
    assert.equal(res.statusCode, 200)
    return { presentation, result: JSON.parse(res.payload) }
  }

  before(async () => {
    const { buildApp } = await import('../../src/index.js')
    wallet = await import('../../src/services/identityWallet.js')
    wallet.resetSharedIssuerKeyStore()
    app = await buildApp()
    const start = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'v2flow.bsky.social' },
    })
    auth = { authorization: `Bearer ${JSON.parse(start.payload).tokens.accessToken}` }
  })

  after(async () => {
    await app.close()
  })

  it('refuses issuance without a proven holder key, without burning the challenge', async () => {
    const me = async () => JSON.parse((await app.inject({ method: 'GET', url: '/v1/sessions/me', headers: auth })).payload).session.issuanceChallenge
    const before = await me()
    const res = await app.inject({
      method: 'POST',
      url: '/v1/identity/ine/credential',
      headers: auth,
      payload: {
        extracted: {},
        verification: {},
        issuanceChallenge: before,
        ageProofs: { over18: { proof: {}, publicSignals: ['1', '2', '3'] } },
      },
    })
    assert.equal(res.statusCode, 400)
    assert.equal(JSON.parse(res.payload).code, 'HOLDER_KEY_PROOF_REQUIRED')
    assert.equal(await me(), before)
  })

  it('issues full and minimized holder-bound credentials under the configured issuer key', async () => {
    const issued = await issueIneCredentialWithClientProof({
      app,
      accessToken: auth.authorization.slice('Bearer '.length),
      inePhotoBase64: 'mock-ine-v2-flow',
      selfieBase64: 'mock-selfie-v2-flow',
    })
    assert.equal(issued.response.statusCode, 200, issued.response.payload)
    holderPrivateKey = issued.holderPrivateKey
    credential = issued.body.credential
    basicCredential = issued.body.basicCredential
    revocationHash = credential.revocationHash

    for (const c of [credential, basicCredential]) {
      assert.equal(c.issuerDid, ISSUER_DID)
      assert.equal(c.issuerKeyId, ISSUER_KEY_ID)
      const { signature, ...payload } = c
      assert.ok(
        verifySignature(null, Buffer.from(stableJson(payload)), issuerKeys.publicKey, Buffer.from(signature, 'base64url')),
        'credential verifies under the configured issuer public key alone',
      )
    }
    assert.ok(credential.claims.curp_hash)
    assert.ok(credential.claims.district_hash)
    assert.deepEqual(basicCredential.claims, { age_over_18: true, citizenship: 'MX' })
    assert.equal(basicCredential.revocationHash, revocationHash)
  })

  it('keeps the demo wallet unavailable', async () => {
    const request = await newRequest(['age_over_18'])
    const res = await app.inject({
      method: 'POST', url: '/v1/identity/present', headers: auth, payload: { requestId: request.id, subjectDid: 'x' },
    })
    assert.equal(res.statusCode, 404)
  })

  it('answers an age-only request with the minimized credential, then rejects its replay', async () => {
    const request = await newRequest(['age_over_18'])

    // The full credential would hand over curp_hash and district_hash; refused,
    // and the refusal does not consume the request.
    const full = await present(request, credential, ['age_over_18'])
    assert.equal(full.result.valid, false)
    assert.ok(full.result.errors.some((e: string) => e.includes('unrequested linkable claim curp_hash')))
    assert.ok(full.result.errors.some((e: string) => e.includes('unrequested linkable claim district_hash')))

    const { presentation, result } = await present(request, basicCredential, ['age_over_18'])
    assert.deepEqual(result.errors, [])
    assert.equal(result.valid, true)
    assert.equal(result.disclosure, 'full-credential')
    assert.deepEqual(result.disclosedClaims, { age_over_18: true })
    assert.deepEqual(result.revealedClaimIds, ['age_over_18', 'citizenship'])
    assert.ok(result.warnings.includes('credential revealed unrequested claim citizenship'))
    assert.ok(!result.warnings.includes('credential revocation status is unknown'))

    const replay = await app.inject({
      method: 'POST',
      url: '/v1/identity/verify',
      headers: auth,
      payload: { requestId: request.id, presentation },
    })
    const replayed = JSON.parse(replay.payload)
    assert.equal(replayed.valid, false)
    assert.ok(replayed.errors.includes('identity request is not active'))
    assert.deepEqual(replayed.disclosedClaims, {})
  })

  it('answers a request for the identifiers with the full credential', async () => {
    const request = await newRequest(ALL_ELEMENTS, ['age_over_18', 'curp_hash'])
    const { result } = await present(request, credential, ['age_over_18', 'curp_hash'])
    assert.deepEqual(result.errors, [])
    assert.equal(result.valid, true)
    assert.deepEqual(result.disclosedClaims, { age_over_18: true, curp_hash: credential.claims.curp_hash })
  })

  it('rejects the credential presented with a different wallet key', async () => {
    const request = await newRequest(['age_over_18'])
    const thief = generateKeyPairSync('ed25519').privateKey
    const { result } = await present(request, basicCredential, ['age_over_18'], thief)
    assert.equal(result.valid, false)
    assert.ok(result.errors.includes('wallet presentation signature is invalid'))
  })

  it('fails closed on a credential the registry never recorded', async () => {
    const holder = generateKeyPairSync('ed25519')
    const session = JSON.parse((await app.inject({ method: 'GET', url: '/v1/sessions/me', headers: auth })).payload).session
    const unrecorded = await wallet.createIssuerSignedCredential({
      subjectDid: session.did,
      claims: { age_over_18: true },
      revocationHash: 'never-recorded',
      holderPublicKey: holder.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    })
    const request = await newRequest(['age_over_18'])
    const { result } = await present(request, unrecorded, ['age_over_18'], holder.privateKey)
    assert.equal(result.valid, false)
    assert.ok(result.errors.includes('credential revocation status is unknown'))
  })

  it('rejects both credentials after the enrollment is revoked', async () => {
    const revoke = await app.inject({
      method: 'POST', url: '/v1/identity/revoke', headers: auth, payload: { revocationHash },
    })
    assert.equal(revoke.statusCode, 200)

    const crl = JSON.parse((await app.inject({ method: 'GET', url: '/v1/identity/crl' })).payload)
    assert.ok(crl.revokedHashes.includes(revocationHash))

    const basic = await present(await newRequest(['age_over_18']), basicCredential, ['age_over_18'])
    assert.equal(basic.result.valid, false)
    assert.ok(basic.result.errors.includes('credential is revoked'))

    const full = await present(await newRequest(ALL_ELEMENTS), credential, ['age_over_18'])
    assert.equal(full.result.valid, false)
    assert.ok(full.result.errors.includes('credential is revoked'))
  })
})
