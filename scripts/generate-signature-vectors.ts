import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { hexToBytes, bytesToHex } from '@noble/curves/abstract/utils'
import { deriveVector } from '../tests/helpers/identityDerivation.js'
import {
  encodeAssertion,
  signAssertion,
  sr25519PublicKey,
  type IdentityAssertion,
  type SigPurpose,
} from '../tests/helpers/identitySignature.js'

/*
 * Regenerates docs/identity-signature-vectors.json from the reference
 * implementation. Same fixed seeds as the derivation vectors, so the two files
 * line up and iM8 can cross-check both from one source.
 *
 *   pnpm exec tsx scripts/generate-signature-vectors.ts
 *
 * The `random` values are fixed so this script is reproducible. Production
 * signers must NOT pass a fixed random — see docs/IDENTITY_SIGNATURES.md.
 */

const SEEDS = [
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0101010101010101010101010101010101010101010101010101010101010101',
  '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
]

const CASES: Array<{ label: 'public' | 'anonymous'; purpose: SigPurpose; audience: string }> = [
  { label: 'public', purpose: 'matrix-login', audience: 'para-idp' },
  { label: 'anonymous', purpose: 'matrix-login', audience: 'para-idp' },
  { label: 'public', purpose: 'mubez-registration', audience: 'mubez' },
]

const SIGNED_AT = '2026-08-24T12:00:00.000Z'
const CHALLENGE = 'c2hhcmVkLXRlc3QtY2hhbGxlbmdl'

const vectors = SEEDS.flatMap((seed) => {
  const derived = deriveVector(hexToBytes(seed)) as any
  return CASES.map(({ label, purpose, audience }) => {
    const identity = derived.identities.find((i: any) => i.label === label)
    const scalar = BigInt('0x' + bytesToHex(hexToBytes(identity.priv).slice().reverse()))
    const pub = sr25519PublicKey(scalar)
    if (bytesToHex(pub) !== identity.pub) {
      throw new Error(
        `sr25519 public key does not match identity_pub for ${seed}/${label}. ` +
          `The cofactor shift is wrong — see docs/IDENTITY_SIGNATURES.md.`,
      )
    }
    const assertion: IdentityAssertion = {
      type: 'para.identity.pop.v1',
      purpose,
      audience,
      identityPub: identity.pub,
      challenge: CHALLENGE,
      signedAt: SIGNED_AT,
    }
    const random = new Uint8Array(32).fill(0x11)
    return {
      seed,
      label,
      purpose,
      // The identity scalar, little-endian hex, as published in the derivation
      // vectors. Included so implementers can reconstruct the secret key.
      privLE: identity.priv,
      audience,
      assertion,
      sr25519PublicKey: bytesToHex(pub),
      encoded: new TextDecoder().decode(encodeAssertion(assertion)),
      signature: signAssertion(scalar, assertion, random),
    }
  })
})

const out = {
  spec: 'docs/IDENTITY_SIGNATURES.md',
  version: 1,
  scheme: 'sr25519 (Schnorr over ristretto255), identity scalar injected cofactor-shifted',
  note:
    'Implementations MUST reproduce `encoded` and `sr25519PublicKey` byte for byte, ' +
    'and MUST verify `signature`. They must NOT be expected to reproduce `signature` ' +
    'byte for byte: sr25519 signatures are randomized.',
  vectors,
}

const path = join(dirname(fileURLToPath(import.meta.url)), '..', 'docs', 'identity-signature-vectors.json')
writeFileSync(path, JSON.stringify(out, null, 2) + '\n')
console.log(`wrote ${path} (${vectors.length} vectors)`)
