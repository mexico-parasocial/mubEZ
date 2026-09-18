import { sha512 } from '@noble/hashes/sha2'
import { numberToBytesLE, bytesToHex } from '@noble/curves/abstract/utils'
import { getPublicKey, sign } from '@scure/sr25519'

/*
 * REFERENCE signer for docs/IDENTITY_SIGNATURES.md.
 *
 * Like identityDerivation.ts this lives under tests/, not src/, and for the
 * same reason: signing requires a private key, and the server must never hold
 * one. Nothing in the service runtime may import this. The server's half of
 * the scheme is verification only — src/services/identitySignature.ts.
 *
 * It exists to generate docs/identity-signature-vectors.json, which iM8's
 * client implementation must satisfy.
 */

const CURVE_ORDER = 2n ** 252n + 27742317777372353535851937790883648493n
const SCALAR_MASK = 2n ** 256n - 1n

export const DOMAIN_IDENTITY_SIG = 'para-id/sig/v1'
export const DOMAIN_SIG_NONCE = 'para-id/sig-nonce/v1'

export type SigPurpose = 'matrix-login' | 'mubez-registration' | 'anon-action'

export interface IdentityAssertion {
  type: 'para.identity.pop.v1'
  purpose: SigPurpose
  audience: string
  identityPub: string
  challenge: string
  signedAt: string
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

/**
 * sr25519 stores the key half cofactor-shifted (scalar << 3) and divides by 8
 * on read. A raw scalar here silently yields a DIFFERENT public key, so this
 * shift is the load-bearing line of the whole scheme.
 */
export function encodeSecretScalar(scalar: bigint): Uint8Array {
  if (scalar <= 0n || scalar >= CURVE_ORDER) {
    throw new Error('scalar out of range')
  }
  return numberToBytesLE((scalar << 3n) & SCALAR_MASK, 32)
}

export function deriveNonceSeed(scalar: bigint): Uint8Array {
  const input = new Uint8Array(DOMAIN_SIG_NONCE.length + 32)
  input.set(utf8(DOMAIN_SIG_NONCE), 0)
  input.set(numberToBytesLE(scalar, 32), DOMAIN_SIG_NONCE.length)
  return sha512(input).subarray(0, 32)
}

export function secretKeyFor(scalar: bigint): Uint8Array {
  const secret = new Uint8Array(64)
  secret.set(encodeSecretScalar(scalar), 0)
  secret.set(deriveNonceSeed(scalar), 32)
  return secret
}

/** Canonical encoding: seven fields joined with LF, domain first. */
export function encodeAssertion(a: IdentityAssertion): Uint8Array {
  return utf8(
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

export function sr25519PublicKey(scalar: bigint): Uint8Array {
  const secret = secretKeyFor(scalar)
  try {
    return getPublicKey(secret)
  } finally {
    secret.fill(0)
  }
}

/**
 * `random` is accepted so vector generation is reproducible. Production
 * signers should omit it and let the library supply randomness — the stored
 * nonce seed already contributes, which is what makes the scheme synthetic.
 */
export function signAssertion(
  scalar: bigint,
  assertion: IdentityAssertion,
  random?: Uint8Array,
): string {
  const secret = secretKeyFor(scalar)
  try {
    return bytesToHex(sign(secret, encodeAssertion(assertion), random))
  } finally {
    secret.fill(0)
  }
}
