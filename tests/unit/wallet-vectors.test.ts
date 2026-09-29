import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import type { M8IdentityRequest, M8TrustedIssuer } from '../../src/types/index.js'

/*
 * docs/wallet-presentation-vectors.json is the contract with the iM8 wallet
 * (CD-14). These tests pin that the vectors are what the verifier accepts;
 * iM8's tests pin that the wallet reproduces them byte for byte.
 */

const vectors = JSON.parse(
  readFileSync(new URL('../../docs/wallet-presentation-vectors.json', import.meta.url), 'utf8'),
)

/** Key order by UTF-16 code unit, with no locale: what a non-Node client does. */
function codePointJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(codePointJson).join(',')}]`
  return `{${Object.keys(value as Record<string, unknown>)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${codePointJson((value as Record<string, unknown>)[k])}`)
    .join(',')}}`
}

describe('wallet conformance vectors', () => {
  let wallet: typeof import('../../src/services/identityWallet.js')

  before(async () => {
    wallet = await import('../../src/services/identityWallet.js')
  })

  it('recomputes the canonical payloads', () => {
    const { signature: _c, ...credential } = vectors.credential.value
    assert.equal(wallet.__internal.signedCredentialPayload(credential), vectors.credential.canonicalPayload)
    const { signature: _p, ...presentation } = vectors.presentation.value
    assert.equal(wallet.__internal.signedPresentationPayload(presentation), vectors.presentation.canonicalPayload)
  })

  it('canonicalizes identically under code-point key order', () => {
    // The verifier sorts keys with localeCompare; clients sort by code point.
    // They must agree on every field name the format uses.
    const { signature: _c, ...credential } = vectors.credential.value
    assert.equal(codePointJson(credential), vectors.credential.canonicalPayload)
    const { signature: _p, ...presentation } = vectors.presentation.value
    assert.equal(codePointJson(presentation), vectors.presentation.canonicalPayload)
  })

  it('accepts the binding proof', () => {
    assert.equal(wallet.holderBindingMessage(vectors.binding.issuanceChallenge), vectors.binding.message)
    assert.equal(
      wallet.verifyHolderKeyProof(vectors.holder.publicKeyPem, vectors.binding.issuanceChallenge, vectors.binding.proof),
      true,
    )
  })

  it('verifies the presentation at the pinned instant', () => {
    const issuer: M8TrustedIssuer = {
      did: vectors.issuer.did,
      keyId: vectors.issuer.keyId,
      name: 'Vector issuer',
      country: 'MX',
      status: 'active',
      publicKeyPem: vectors.issuer.publicKeyPem,
      allowedElements: ['age_over_18', 'age_over_21', 'citizenship', 'district_hash', 'curp_hash'],
    }
    const request: M8IdentityRequest = {
      ...vectors.request,
      sessionId: 'vector-session',
      audienceAppName: 'Vector verifier',
      purpose: 'Conformance',
      merchantIdentifier: 'merchant.vector',
      requestedElements: [{ id: 'age_over_18', intentToStore: { mode: 'will-not-store' }, required: true }],
      status: 'active',
      createdAt: '2026-09-02T08:59:00.000Z',
      expiresAt: '2026-09-02T09:04:00.000Z',
      usedAt: null,
    }
    const result = wallet.verifyWalletPresentation(request, vectors.presentation.value, {
      expectedSubjectDid: vectors.credential.value.subjectDid,
      trustedIssuers: [issuer],
      revocationStatus: () => 'active',
      now: Date.parse(vectors.verifyAt),
    })
    assert.deepEqual(result.errors, [])
    assert.equal(result.valid, true)
    assert.deepEqual(result.revealedClaimIds, ['age_over_18', 'citizenship'])
  })
})
