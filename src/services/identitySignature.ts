import { verify } from '@scure/sr25519'

/*
 * Verifier for PARA identity proof of possession.
 * Spec: docs/IDENTITY_SIGNATURES.md · decision: CRYPTO_DECISIONS.md CD-7
 *
 * Verification only. This module holds no private key material and needs none
 * — the server's entire role is checking that a client holds the key it
 * claims. The reference signer lives under tests/helpers/, deliberately
 * outside the service runtime.
 *
 * Used by mubEZ registration (purpose "mubez-registration") and, in WatZappa,
 * by para-idp before it issues an OIDC assertion to Matrix (purpose
 * "matrix-login"). Both sign with the same identity key, which is why purpose
 * is inside the signed bytes rather than checked alongside them.
 */

export const DOMAIN_IDENTITY_SIG = 'para-id/sig/v1'

export const SIG_PURPOSES = ['matrix-login', 'mubez-registration', 'anon-action'] as const
export type SigPurpose = (typeof SIG_PURPOSES)[number]

export interface IdentityAssertion {
  type: 'para.identity.pop.v1'
  purpose: SigPurpose
  audience: string
  identityPub: string
  challenge: string
  signedAt: string
}

export interface SignedAssertion {
  assertion: IdentityAssertion
  /** 64-byte sr25519 signature, hex. */
  signature: string
}

export interface VerifyExpectation {
  purpose: SigPurpose
  audience: string
  /** The outstanding challenge. Callers must also consume it — see below. */
  challenge: string
  /** Max age of `signedAt`. Defaults to 5 minutes. */
  maxAgeMs?: number
  now?: Date
}

const DEFAULT_MAX_AGE_MS = 5 * 60 * 1000

function hexToBytes(hex: string, length: number): Uint8Array {
  if (typeof hex !== 'string' || hex.length !== length * 2) {
    throw new Error('bad hex length')
  }
  const out = new Uint8Array(length)
  for (let i = 0; i < length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    if (Number.isNaN(byte)) throw new Error('bad hex')
    out[i] = byte
  }
  return out
}

export function encodeAssertion(a: IdentityAssertion): Uint8Array {
  return new TextEncoder().encode(
    [
      DOMAIN_IDENTITY_SIG,
      a.type,
      a.purpose,
      a.audience,
      a.identityPub,
      a.challenge,
      a.signedAt,
    ].join('\n'),
  )
}

/**
 * Verify a proof of possession.
 *
 * Returns a boolean and never throws. Everything reaching this function is
 * attacker-controlled: `@scure/sr25519`'s `verify()` raises on a malformed
 * point, and a null body raises before any field is read. Unguarded, both turn
 * garbage input into a 500 rather than an authentication failure.
 *
 * **The caller must consume the challenge** on success — this function cannot,
 * since it holds no database handle. Use
 * `rotateIssuanceChallenge(sessionId)` immediately after a true result, or the
 * signature is replayable for as long as the challenge stands.
 */
export function verifyIdentityAssertion(
  signed: SignedAssertion,
  expected: VerifyExpectation,
): boolean {
  try {
    if (!signed || typeof signed !== 'object') return false
    const { assertion, signature } = signed
    if (!assertion || typeof assertion !== 'object') return false
    if (typeof signature !== 'string') return false

    if (assertion.type !== 'para.identity.pop.v1') return false
    // Never accept "any purpose": both consumers sign with the same key, so a
    // registration assertion must not be usable as a Matrix login.
    if (assertion.purpose !== expected.purpose) return false
    if (assertion.audience !== expected.audience) return false
    if (assertion.challenge !== expected.challenge) return false

    const signedAt = Date.parse(assertion.signedAt)
    if (Number.isNaN(signedAt)) return false
    const now = (expected.now ?? new Date()).getTime()
    const maxAge = expected.maxAgeMs ?? DEFAULT_MAX_AGE_MS
    // Reject stale assertions, and future-dated ones beyond small clock skew.
    if (signedAt > now + 60_000) return false
    if (now - signedAt > maxAge) return false

    const pub = hexToBytes(assertion.identityPub, 32)
    const sig = hexToBytes(signature, 64)
    return verify(encodeAssertion(assertion), sig, pub)
  } catch {
    return false
  }
}
