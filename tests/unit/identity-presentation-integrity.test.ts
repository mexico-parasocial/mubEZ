import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, sign } from 'node:crypto'
import type { M8IdentityCredential, M8IdentityRequest, M8WalletPresentation } from '../../src/types/index.js'

/*
 * Presentation integrity at /identity/verify: disclosed claims must equal the
 * issuer-signed claims, the presentation must be signed by the holder key the
 * issuer bound into the credential, and it must be bound to the requesting
 * session's DID and to one live request.
 */

const issuerKeys = generateKeyPairSync('ed25519')
const SUBJECT = 'did:plc:presentation-subject'

type Wallet = typeof import('../../src/services/identityWallet.js')
let wallet: Wallet

function newHolder() {
  const keys = generateKeyPairSync('ed25519')
  return {
    privateKey: keys.privateKey,
    publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  }
}

function request(overrides: Partial<M8IdentityRequest> = {}): M8IdentityRequest {
  return {
    ...wallet.createIdentityRequest('presentation-session', {
      audienceAppId: 'integrity.test',
      audienceAppName: 'Integrity Test',
      purpose: 'Presentation integrity',
      requestedElements: [
        { id: 'age_over_18', intentToStore: { mode: 'will-not-store' }, required: true },
        { id: 'age_over_21', intentToStore: { mode: 'will-not-store' }, required: false },
        { id: 'citizenship', intentToStore: { mode: 'will-not-store' }, required: false },
      ],
    }),
    ...overrides,
  }
}

async function credentialFor(holderPublicKey: string, claims: M8IdentityCredential['claims'] = {
  age_over_18: true,
  age_over_21: false,
  citizenship: 'MX',
}) {
  return wallet.createIssuerSignedCredential({
    subjectDid: SUBJECT,
    claims,
    revocationHash: `rev-${Math.random().toString(36).slice(2)}`,
    holderPublicKey,
  })
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`
  return `{${Object.entries(value as Record<string, unknown>)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${JSON.stringify(k)}:${stableJson(v)}`)
    .join(',')}}`
}

/** A credential as issued before holder binding: issuer-signed, no holder key. */
function legacyUnboundCredential(): M8IdentityCredential {
  const unsigned = {
    id: 'credential-legacy',
    issuerDid: 'did:m8:ine:integrity-issuer',
    issuerKeyId: 'integrity-key',
    subjectDid: SUBJECT,
    issuedAt: new Date(Date.now() - 1000).toISOString(),
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    claims: { age_over_18: true },
    revocationHash: 'rev-legacy',
    signatureAlg: 'Ed25519' as const,
  }
  return {
    ...unsigned,
    signature: sign(null, Buffer.from(stableJson(unsigned)), issuerKeys.privateKey).toString('base64url'),
  }
}

/** Re-signs a hand-edited presentation with the given key, as a malicious wallet would. */
function resign(presentation: Omit<M8WalletPresentation, 'signature'> & { signature?: string }, privateKey: import('node:crypto').KeyObject) {
  const { signature: _drop, ...unsigned } = presentation
  const stable = (value: unknown): string => {
    if (value === null || typeof value !== 'object') return JSON.stringify(value)
    if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${JSON.stringify(k)}:${stable(v)}`)
      .join(',')}}`
  }
  return { ...unsigned, signature: sign(null, Buffer.from(stable(unsigned)), privateKey).toString('base64url') }
}

function verify(req: M8IdentityRequest, presentation: unknown, overrides: Partial<import('../../src/services/identityWallet.js').PresentationVerificationOptions> = {}) {
  return wallet.verifyWalletPresentation(req, presentation, {
    expectedSubjectDid: SUBJECT,
    revocationStatus: () => 'active',
    ...overrides,
  })
}

describe('identity presentation integrity', () => {
  before(async () => {
    process.env.IDENTITY_ISSUER_DID = 'did:m8:ine:integrity-issuer'
    process.env.IDENTITY_ISSUER_PRIVATE_JWK = JSON.stringify(issuerKeys.privateKey.export({ format: 'jwk' }))
    process.env.IDENTITY_ISSUER_PUBLIC_JWK = JSON.stringify(issuerKeys.publicKey.export({ format: 'jwk' }))
    process.env.IDENTITY_ISSUER_KEY_ID = 'integrity-key'
    for (const key of ['IDENTITY_ISSUER_PREVIOUS_PUBLIC_JWK', 'IDENTITY_ISSUER_PREVIOUS_KEY_ID', 'IDENTITY_ISSUER_PREVIOUS_KEY_EXPIRES_AT', 'IDENTITY_ISSUER_REVOKED_KEY_IDS']) {
      delete process.env[key]
    }
    wallet = await import('../../src/services/identityWallet.js')
    wallet.resetSharedIssuerKeyStore()
  })

  it('accepts a legitimate holder-bound presentation', async () => {
    const holder = newHolder()
    const req = request()
    const credential = await credentialFor(holder.publicKeyPem)
    const presentation = wallet.signWalletPresentation({
      request: req, credential, disclosedClaimIds: ['age_over_18', 'citizenship'], holderPrivateKey: holder.privateKey,
    })

    const result = verify(req, presentation)
    assert.deepEqual(result.errors, [])
    assert.equal(result.valid, true)
    assert.deepEqual(result.disclosedClaims, { age_over_18: true, citizenship: 'MX' })
    assert.equal(result.disclosure, 'full-credential')
    assert.deepEqual(result.revealedClaimIds.sort(), ['age_over_18', 'age_over_21', 'citizenship'])
    assert.equal(result.subjectDid, SUBJECT)
  })

  it('rejects a disclosed claim whose value differs from the signed credential', async () => {
    const holder = newHolder()
    const req = request()
    const credential = await credentialFor(holder.publicKeyPem)
    const honest = wallet.signWalletPresentation({
      request: req, credential, disclosedClaimIds: ['age_over_18', 'age_over_21'], holderPrivateKey: holder.privateKey,
    })
    const lying = resign({ ...honest, disclosedClaims: { age_over_18: true, age_over_21: true } }, holder.privateKey)

    const result = verify(req, lying)
    assert.equal(result.valid, false)
    assert.ok(result.errors.includes('claim age_over_21 does not match the credential'))
    assert.deepEqual(result.disclosedClaims, {})
  })

  it('rejects an invented claim that the credential does not contain', async () => {
    const holder = newHolder()
    const req = request()
    const credential = await credentialFor(holder.publicKeyPem, { age_over_18: true })
    const honest = wallet.signWalletPresentation({
      request: req, credential, disclosedClaimIds: ['age_over_18'], holderPrivateKey: holder.privateKey,
    })
    const invented = resign({ ...honest, disclosedClaims: { age_over_18: true, citizenship: 'MX' } }, holder.privateKey)

    const result = verify(req, invented)
    assert.equal(result.valid, false)
    assert.ok(result.errors.includes('claim citizenship is not in the credential'))
  })

  it('rejects edits to the signed credential claims', async () => {
    const holder = newHolder()
    const req = request()
    const credential = await credentialFor(holder.publicKeyPem)
    const edited = resign({
      ...wallet.signWalletPresentation({ request: req, credential, disclosedClaimIds: ['age_over_21'], holderPrivateKey: holder.privateKey }),
      credential: { ...credential, claims: { ...credential.claims, age_over_21: true } },
      disclosedClaims: { age_over_21: true },
    }, holder.privateKey)

    const result = verify(req, edited)
    assert.equal(result.valid, false)
    assert.ok(result.errors.includes('credential issuer signature is invalid'))
  })

  it('rejects malformed claims and unknown fields', async () => {
    const holder = newHolder()
    const req = request()
    const credential = await credentialFor(holder.publicKeyPem)
    const honest = wallet.signWalletPresentation({
      request: req, credential, disclosedClaimIds: ['age_over_18'], holderPrivateKey: holder.privateKey,
    })

    const wrongType = verify(req, resign({ ...honest, disclosedClaims: { age_over_18: 'true' } as never }, holder.privateKey))
    assert.equal(wrongType.valid, false)
    assert.ok(wrongType.errors.some((e) => e.startsWith('malformed presentation: disclosedClaims.age_over_18')))

    const unknownClaim = verify(req, resign({ ...honest, disclosedClaims: { age_over_18: true, is_admin: true } as never }, holder.privateKey))
    assert.equal(unknownClaim.valid, false)
    assert.ok(unknownClaim.errors.some((e) => e.startsWith('malformed presentation: disclosedClaims')))

    const extraField = verify(req, resign({ ...honest, devicePublicKey: holder.publicKeyPem } as never, holder.privateKey))
    assert.equal(extraField.valid, false)

    const badDate = verify(req, resign({ ...honest, expiresAt: 'not-a-date' }, holder.privateKey))
    assert.equal(badDate.valid, false)
    assert.ok(badDate.errors.some((e) => e.startsWith('malformed presentation: expiresAt')))

    assert.equal(verify(req, null).valid, false)
    assert.equal(verify(req, 'presentation').valid, false)
  })

  it('rejects a stolen credential presented with a new wallet key', async () => {
    const victim = newHolder()
    const attacker = newHolder()
    const req = request()
    const credential = await credentialFor(victim.publicKeyPem)

    // The attacker signs with their own key and cannot touch the holder key.
    const stolen = wallet.signWalletPresentation({
      request: req, credential, disclosedClaimIds: ['age_over_18'], holderPrivateKey: attacker.privateKey,
    })
    const result = verify(req, stolen)
    assert.equal(result.valid, false)
    assert.ok(result.errors.includes('wallet presentation signature is invalid'))

    // Swapping in their own holder key breaks the issuer signature instead.
    const swapped = wallet.signWalletPresentation({
      request: req,
      credential: { ...credential, holderPublicKey: attacker.publicKeyPem.trim() },
      disclosedClaimIds: ['age_over_18'],
      holderPrivateKey: attacker.privateKey,
    })
    const swappedResult = verify(req, swapped)
    assert.equal(swappedResult.valid, false)
    assert.ok(swappedResult.errors.includes('credential issuer signature is invalid'))
  })

  it('rejects the v1 format and credentials without an issuer-signed holder key', async () => {
    const attacker = newHolder()
    const req = request()
    const unbound = legacyUnboundCredential()
    // Still a valid issuer signature, so the refusal below is about the holder key.
    assert.equal(verify(req, wallet.signWalletPresentation({
      request: req, credential: { ...unbound, holderPublicKey: attacker.publicKeyPem.trim() }, disclosedClaimIds: ['age_over_18'], holderPrivateKey: attacker.privateKey,
    })).errors.includes('credential issuer signature is invalid'), true)

    const v1 = resign({
      type: 'm8.identity.presentation.v1',
      requestId: req.id,
      nonce: req.nonce,
      audienceAppId: req.audienceAppId,
      credential: unbound,
      disclosedClaims: { age_over_18: true },
      devicePublicKey: attacker.publicKeyPem,
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      signatureAlg: 'Ed25519',
    } as never, attacker.privateKey)
    const v1Result = verify(req, v1)
    assert.equal(v1Result.valid, false)
    assert.match(v1Result.errors[0], /m8\.identity\.presentation\.v1 is not accepted/)

    const unboundV2 = wallet.signWalletPresentation({
      request: req, credential: unbound, disclosedClaimIds: ['age_over_18'], holderPrivateKey: attacker.privateKey,
    })
    const unboundResult = verify(req, unboundV2)
    assert.equal(unboundResult.valid, false)
    assert.ok(unboundResult.errors.includes('credential has no issuer-signed holder key'))
  })

  it('rejects a credential whose subject is not the requesting session DID', async () => {
    const holder = newHolder()
    const req = request()
    const credential = await credentialFor(holder.publicKeyPem)
    const presentation = wallet.signWalletPresentation({
      request: req, credential, disclosedClaimIds: ['age_over_18'], holderPrivateKey: holder.privateKey,
    })

    const result = verify(req, presentation, { expectedSubjectDid: 'did:plc:someone-else' })
    assert.equal(result.valid, false)
    assert.ok(result.errors.includes('credential subject does not match the requesting session'))
  })

  it('rejects a presentation made for a different request', async () => {
    const holder = newHolder()
    const reqA = request()
    const reqB = request()
    const credential = await credentialFor(holder.publicKeyPem)
    const forA = wallet.signWalletPresentation({
      request: reqA, credential, disclosedClaimIds: ['age_over_18'], holderPrivateKey: holder.privateKey,
    })

    const result = verify(reqB, forA)
    assert.equal(result.valid, false)
    assert.ok(result.errors.includes('presentation requestId does not match'))
    assert.ok(result.errors.includes('presentation nonce does not match'))

    const otherAudience = verify({ ...reqA, audienceAppId: 'other.app' }, forA)
    assert.ok(otherAudience.errors.includes('presentation audience does not match'))
  })

  it('rejects replay against a consumed request', async () => {
    const holder = newHolder()
    const req = request()
    const credential = await credentialFor(holder.publicKeyPem)
    const presentation = wallet.signWalletPresentation({
      request: req, credential, disclosedClaimIds: ['age_over_18'], holderPrivateKey: holder.privateKey,
    })
    assert.equal(verify(req, presentation).valid, true)

    const replay = verify({ ...req, status: 'used', usedAt: new Date().toISOString() }, presentation)
    assert.equal(replay.valid, false)
    assert.ok(replay.errors.includes('identity request is not active'))
  })

  it('rejects expired presentations and credentials', async () => {
    const holder = newHolder()
    const req = request()
    const expiredCredential = await wallet.createIssuerSignedCredential({
      subjectDid: SUBJECT,
      claims: { age_over_18: true },
      revocationHash: 'rev-expired',
      holderPublicKey: holder.publicKeyPem,
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    })
    const result = verify(req, wallet.signWalletPresentation({
      request: req, credential: expiredCredential, disclosedClaimIds: ['age_over_18'], holderPrivateKey: holder.privateKey,
    }))
    assert.ok(result.errors.includes('credential expired'))

    const credential = await credentialFor(holder.publicKeyPem)
    const honest = wallet.signWalletPresentation({
      request: req, credential, disclosedClaimIds: ['age_over_18'], holderPrivateKey: holder.privateKey,
    })
    const stale = resign({
      ...honest,
      issuedAt: new Date(Date.now() - 120_000).toISOString(),
      expiresAt: new Date(Date.now() - 30_000).toISOString(),
    }, holder.privateKey)
    assert.ok(verify(req, stale).errors.includes('presentation expired'))

    const longLived = resign({ ...honest, expiresAt: new Date(Date.now() + 24 * 3600_000).toISOString() }, holder.privateKey)
    assert.ok(verify(req, longLived).errors.includes('presentation lifetime exceeds the allowed maximum'))

    assert.ok(verify({ ...req, expiresAt: new Date(Date.now() - 1000).toISOString() }, honest).errors.includes('identity request expired'))
  })

  it('checks revocation status and fails closed on unknown credentials', async () => {
    const holder = newHolder()
    const req = request()
    const credential = await credentialFor(holder.publicKeyPem)
    const presentation = wallet.signWalletPresentation({
      request: req, credential, disclosedClaimIds: ['age_over_18'], holderPrivateKey: holder.privateKey,
    })

    assert.ok(verify(req, presentation, { revocationStatus: () => 'revoked' }).errors.includes('credential is revoked'))
    assert.ok(verify(req, presentation, { revocationStatus: () => 'suspended' }).errors.includes('credential is suspended'))
    assert.ok(verify(req, presentation, { revocationStatus: () => 'unknown' }).errors.includes('credential revocation status is unknown'))

    const lenient = verify(req, presentation, { revocationStatus: () => 'unknown', rejectUnknownRevocationStatus: false })
    assert.equal(lenient.valid, true)
    assert.ok(lenient.warnings.includes('credential revocation status is unknown'))
  })

  it('refuses to reveal unrequested linkable claims under full-credential disclosure', async () => {
    const holder = newHolder()
    const req = request()
    const credential = await credentialFor(holder.publicKeyPem, {
      age_over_18: true,
      curp_hash: 'hmac:curp:abc',
    })
    const presentation = wallet.signWalletPresentation({
      request: req, credential, disclosedClaimIds: ['age_over_18'], holderPrivateKey: holder.privateKey,
    })

    const result = verify(req, presentation)
    assert.equal(result.valid, false)
    assert.ok(result.errors.some((e) => e.includes('unrequested linkable claim curp_hash')))
  })

  it('refuses to issue a credential without a valid holder key', async () => {
    const base = { subjectDid: SUBJECT, claims: { age_over_18: true }, revocationHash: 'rev-refused' }
    await assert.rejects(wallet.createIssuerSignedCredential({ ...base, holderPublicKey: '' }), /Ed25519/)
    await assert.rejects(wallet.createIssuerSignedCredential({ ...base, holderPublicKey: 'not a key' }), /Ed25519/)
    const rsa = generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ type: 'spki', format: 'pem' }).toString()
    await assert.rejects(wallet.createIssuerSignedCredential({ ...base, holderPublicKey: rsa }), /Ed25519/)
  })

  it('minimizes claims to proven, non-linkable ones', () => {
    assert.deepEqual(
      wallet.minimizedCredentialClaims({
        age_over_18: true, age_over_21: false, citizenship: 'MX', district_hash: 'd', curp_hash: 'c',
      }),
      { age_over_18: true, citizenship: 'MX' },
    )
  })

  it('verifies holder proof of possession over the issuance challenge', () => {
    const holder = newHolder()
    const other = newHolder()
    const challenge = 'challenge-abc'
    const proof = sign(null, Buffer.from(wallet.holderBindingMessage(challenge)), holder.privateKey).toString('base64url')

    assert.equal(wallet.verifyHolderKeyProof(holder.publicKeyPem, challenge, proof), true)
    assert.equal(wallet.verifyHolderKeyProof(holder.publicKeyPem, 'other-challenge', proof), false)
    assert.equal(wallet.verifyHolderKeyProof(other.publicKeyPem, challenge, proof), false)
    assert.equal(wallet.verifyHolderKeyProof('not a key', challenge, proof), false)
  })
})
