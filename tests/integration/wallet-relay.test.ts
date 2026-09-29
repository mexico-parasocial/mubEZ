import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'
import type { M8IdentityCredential, M8IdentityRequest } from '../../src/types/index.js'
import { buildAgeProofs } from '../helpers/clientProof.js'

/*
 * CD-14 relay, end to end over HTTP with both apps on one M8 session: "PARA"
 * never touches a key or a credential; "the wallet" holds its private key and
 * sends only public keys, proofs and signed presentations. Configured issuer
 * key, demo wallet off (strict revocation), simulated INE as the only issuance
 * route this codebase has.
 */

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-wallet-relay-'))
process.env.DATABASE_PATH = join(tmpDir, 'wallet-relay.db')
const issuerKeys = generateKeyPairSync('ed25519')
process.env.IDENTITY_ISSUER_DID = 'did:m8:ine:relay-issuer'
process.env.IDENTITY_ISSUER_KEY_ID = 'ine-ed25519-relay'
process.env.IDENTITY_ISSUER_PRIVATE_JWK = JSON.stringify(issuerKeys.privateKey.export({ format: 'jwk' }))
process.env.IDENTITY_ISSUER_PUBLIC_JWK = JSON.stringify(issuerKeys.publicKey.export({ format: 'jwk' }))
for (const key of ['IDENTITY_ISSUER_PREVIOUS_PUBLIC_JWK', 'IDENTITY_ISSUER_PREVIOUS_KEY_ID', 'IDENTITY_ISSUER_PREVIOUS_KEY_EXPIRES_AT', 'IDENTITY_ISSUER_REVOKED_KEY_IDS']) {
  delete process.env[key]
}
// Several enrollments in one minute; the auth-category limit is not under test.
process.env.RATE_LIMIT_AUTH_MAX = '1000'
process.env.GROWTHBOOK_FEATURE_OVERRIDES = JSON.stringify({
  'm8:auth:dev_token_bootstrap': true,
  'm8:demo_identity_wallet:enable': false,
  'm8:simulated_ine:enable': true,
})

type Delivery = { proofArtifactId: string; credential: M8IdentityCredential; basicCredential: M8IdentityCredential }

describe('iM8 wallet relay (CD-14)', () => {
  let app: TestApp
  let auth: Record<string, string>
  let wallet: typeof import('../../src/services/identityWallet.js')

  const call = async (method: string, url: string, payload?: unknown, headers = auth) => {
    const res = await app.inject({ method, url, headers, payload })
    return { status: res.statusCode, body: res.payload ? JSON.parse(res.payload) : undefined }
  }

  /** The wallet's half of a binding: a fresh device key, proof over the snapshotted challenge. */
  function deviceKey() {
    const keys = generateKeyPairSync('ed25519')
    return { privateKey: keys.privateKey, publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }
  }
  const proofFor = (key: KeyObject, challenge: string) =>
    sign(null, Buffer.from(wallet.holderBindingMessage(challenge)), key).toString('base64url')

  /** PARA's half of an INE issuance, bound through the relay. */
  async function paraIssue(bindingId: string, issuanceChallenge: string, photo: string) {
    const extracted = (await call('POST', '/v1/identity/ine/analyze', { inePhotoBase64: photo, simulatedMode: true })).body.extracted
    const verification = (await call('POST', '/v1/identity/ine/verify', { extracted, selfieBase64: `${photo}-selfie`, consentToStore: true })).body
    const { ageProofs } = await buildAgeProofs({ birthDate: extracted.birthDate })
    return call('POST', '/v1/identity/ine/credential', {
      extracted, verification, issuanceChallenge, ageProofs, walletBindingRequestId: bindingId,
    })
  }

  /** Full enrollment through the relay; returns what the wallet ends up holding. */
  async function enrollThroughRelay(photo: string) {
    const binding = (await call('POST', '/v1/identity/wallet/binding-requests')).body
    const key = deviceKey()
    const bound = await call('POST', `/v1/identity/wallet/binding-requests/${binding.id}/fulfill`, {
      holderPublicKey: key.publicKeyPem, holderKeyProof: proofFor(key.privateKey, binding.issuanceChallenge),
    })
    assert.equal(bound.status, 200)
    const issued = await paraIssue(binding.id, binding.issuanceChallenge, photo)
    assert.equal(issued.status, 200, JSON.stringify(issued.body))
    const collected = await call('POST', `/v1/identity/wallet/binding-requests/${binding.id}/collect`)
    assert.equal(collected.status, 200)
    return { key, delivery: collected.body as Delivery, issuedBody: issued.body, bindingId: binding.id }
  }

  async function ageRequest() {
    return (await call('POST', '/v1/identity/request', {
      audienceAppId: 'para.age-gate',
      audienceAppName: 'PARA age gate',
      purpose: 'Age-restricted community',
      requestedElements: [{ id: 'age_over_18', intentToStore: { mode: 'will-not-store' }, required: true }],
    })).body as M8IdentityRequest
  }

  async function walletPresents(request: M8IdentityRequest, credential: M8IdentityCredential, key: KeyObject) {
    const presentation = wallet.signWalletPresentation({
      request, credential, disclosedClaimIds: ['age_over_18'], holderPrivateKey: key,
    })
    return (await call('POST', '/v1/identity/verify', { requestId: request.id, presentation })).body
  }

  before(async () => {
    const { buildApp } = await import('../../src/index.js')
    wallet = await import('../../src/services/identityWallet.js')
    wallet.resetSharedIssuerKeyStore()
    app = await buildApp()
    const start = await app.inject({ method: 'POST', url: '/v1/sessions/start', payload: { identifier: 'relayholder.bsky.social' } })
    auth = { authorization: `Bearer ${JSON.parse(start.payload).tokens.accessToken}` }
  })

  after(async () => {
    await app.close()
  })

  let first: Awaited<ReturnType<typeof enrollThroughRelay>>

  it('binds a device key and delivers the credentials to the wallet, not to PARA', async () => {
    const binding = (await call('POST', '/v1/identity/wallet/binding-requests')).body
    assert.equal(binding.status, 'pending')

    const listed = (await call('GET', '/v1/identity/wallet/binding-requests')).body.requests
    assert.ok(listed.some((r: { id: string }) => r.id === binding.id))

    // Not bound yet: issuance is refused and the challenge survives.
    const early = await paraIssue(binding.id, binding.issuanceChallenge, 'mock-relay-early')
    assert.equal(early.status, 400)
    assert.equal(early.body.code, 'WALLET_BINDING_NOT_READY')

    const key = deviceKey()
    const forged = await call('POST', `/v1/identity/wallet/binding-requests/${binding.id}/fulfill`, {
      holderPublicKey: key.publicKeyPem, holderKeyProof: proofFor(deviceKey().privateKey, binding.issuanceChallenge),
    })
    assert.equal(forged.status, 400)
    assert.equal(forged.body.error, 'invalid-proof')

    const bound = await call('POST', `/v1/identity/wallet/binding-requests/${binding.id}/fulfill`, {
      holderPublicKey: key.publicKeyPem, holderKeyProof: proofFor(key.privateKey, binding.issuanceChallenge),
    })
    assert.equal(bound.status, 200)

    const polled = (await call('GET', `/v1/identity/wallet/binding-requests/${binding.id}`)).body
    assert.equal(polled.status, 'bound')
    assert.equal(Object.hasOwn(polled, 'holderPublicKey'), false)

    const issued = await paraIssue(binding.id, binding.issuanceChallenge, 'mock-relay-first')
    assert.equal(issued.status, 200, JSON.stringify(issued.body))
    assert.equal(issued.body.credentialDelivery, 'wallet')
    assert.equal(Object.hasOwn(issued.body, 'credential'), false)
    assert.equal(Object.hasOwn(issued.body, 'basicCredential'), false)

    const collected = await call('POST', `/v1/identity/wallet/binding-requests/${binding.id}/collect`)
    assert.equal(collected.status, 200)
    const delivery = collected.body as Delivery
    assert.equal(delivery.proofArtifactId, issued.body.proofArtifactId)
    assert.equal(delivery.credential.holderPublicKey, key.publicKeyPem.trim())
    assert.equal(delivery.basicCredential.holderPublicKey, key.publicKeyPem.trim())

    // Collected once, then erased from the relay.
    assert.equal((await call('POST', `/v1/identity/wallet/binding-requests/${binding.id}/collect`)).status, 404)
    first = { key, delivery, issuedBody: issued.body, bindingId: binding.id }
  })

  it('refuses a binding used against a rotated challenge, or mixed with a direct proof', async () => {
    const binding = (await call('POST', '/v1/identity/wallet/binding-requests')).body
    const key = deviceKey()
    await call('POST', `/v1/identity/wallet/binding-requests/${binding.id}/fulfill`, {
      holderPublicKey: key.publicKeyPem, holderKeyProof: proofFor(key.privateKey, binding.issuanceChallenge),
    })

    const mixed = await call('POST', '/v1/identity/ine/credential', {
      extracted: {}, verification: {}, issuanceChallenge: binding.issuanceChallenge,
      ageProofs: { over18: { proof: {}, publicSignals: ['1', '2', '3'] } },
      walletBindingRequestId: binding.id, holderPublicKey: key.publicKeyPem, holderKeyProof: 'x',
    })
    assert.equal(mixed.body.code, 'HOLDER_BINDING_AMBIGUOUS')

    // Another issuance rotates the session challenge; this binding is now stale.
    await enrollThroughRelay('mock-relay-rotator')
    const stale = await paraIssue(binding.id, binding.issuanceChallenge, 'mock-relay-stale')
    assert.equal(stale.status, 403)
    const current = (await call('GET', '/v1/sessions/me')).body.session.issuanceChallenge
    const mismatched = await paraIssue(binding.id, current, 'mock-relay-stale')
    assert.equal(mismatched.body.code, 'WALLET_BINDING_NOT_READY')
  })

  it('uses the identity request as the presentation mailbox, with a read-once result', async () => {
    const request = await ageRequest()

    const pending = (await call('GET', '/v1/identity/requests')).body.requests
    assert.ok(pending.some((r: { id: string }) => r.id === request.id))

    const result = await walletPresents(request, first.delivery.basicCredential, first.key.privateKey)
    assert.deepEqual(result.errors, [])
    assert.equal(result.valid, true)

    const outcome = (await call('GET', `/v1/identity/request/${request.id}`)).body
    assert.equal(outcome.status, 'used')
    assert.deepEqual(outcome.result.disclosedClaims, { age_over_18: true })
    assert.deepEqual(outcome.result.revealedClaimIds, ['age_over_18', 'citizenship'])
    assert.equal(Object.hasOwn(outcome.result, 'subjectDid'), false)

    const again = (await call('GET', `/v1/identity/request/${request.id}`)).body
    assert.equal(again.resultDelivered, true)
    assert.equal(Object.hasOwn(again, 'result'), false)

    assert.ok(!(await call('GET', '/v1/identity/requests')).body.requests.some((r: { id: string }) => r.id === request.id))
  })

  it('lets the wallet decline a request', async () => {
    const request = await ageRequest()
    assert.equal((await call('POST', `/v1/identity/request/${request.id}/decline`)).status, 200)
    assert.equal((await call('GET', `/v1/identity/request/${request.id}`)).body.status, 'declined')
    const late = await walletPresents(request, first.delivery.basicCredential, first.key.privateKey)
    assert.equal(late.valid, false)
    assert.ok(late.errors.includes('identity request is not active'))
  })

  it('recovers from device loss: revoke by artifact id, re-enroll with a new key', async () => {
    // The replacement device holds no key and no credential. It sees the
    // session's INE artifacts and revokes the ones it cannot present.
    const proofs = (await call('GET', '/v1/sessions/me')).body.session.proofs as Array<{ id: string; requestId: string; status: string }>
    const lost = proofs.filter((p) => p.requestId === 'ine-verification' && p.status === 'active')
    assert.ok(lost.some((p) => p.id === first.delivery.proofArtifactId))
    for (const artifact of lost) {
      assert.equal((await call('POST', '/v1/identity/revoke', { proofArtifactId: artifact.id })).status, 200)
    }

    // Whoever holds the lost device's key can no longer pass the gate with it.
    const stolen = await walletPresents(await ageRequest(), first.delivery.basicCredential, first.key.privateKey)
    assert.equal(stolen.valid, false)
    assert.ok(stolen.errors.includes('credential is revoked'))

    const replacement = await enrollThroughRelay('mock-relay-replacement')
    assert.notEqual(replacement.key.publicKeyPem, first.key.publicKeyPem)
    const fresh = await walletPresents(await ageRequest(), replacement.delivery.basicCredential, replacement.key.privateKey)
    assert.deepEqual(fresh.errors, [])
    assert.equal(fresh.valid, true)
  })

  it('refuses to revoke another session\'s artifact by id', async () => {
    const other = await app.inject({ method: 'POST', url: '/v1/sessions/start', payload: { identifier: 'relayother.bsky.social' } })
    const otherAuth = { authorization: `Bearer ${JSON.parse(other.payload).tokens.accessToken}` }
    const proofs = (await call('GET', '/v1/sessions/me')).body.session.proofs as Array<{ id: string; requestId: string; status: string }>
    const target = proofs.find((p) => p.requestId === 'ine-verification' && p.status === 'active')!
    const res = await call('POST', '/v1/identity/revoke', { proofArtifactId: target.id }, otherAuth)
    assert.equal(res.status, 403)
  })
})
