import { sha512 } from '@noble/hashes/sha2'
import { RistrettoPoint, ed25519 } from '@noble/curves/ed25519'
import { bytesToNumberLE, numberToBytesLE, bytesToHex } from '@noble/curves/abstract/utils'

/*
 * REFERENCE implementation of the PARA identity derivation spec
 * (docs/IDENTITY_DERIVATION.md). It exists to generate and validate the
 * shared test vectors. It deliberately lives under tests/, not src/: the
 * server must never hold a user's seed or private keys, so nothing in the
 * service runtime may import this.
 *
 * iM8 implements the same math client-side and must reproduce
 * docs/identity-derivation-vectors.json byte for byte.
 */

const L = ed25519.CURVE.n

export const DOMAIN_SPEND = 'm8/derive/spend/v1'
export const DOMAIN_VIEW = 'm8/derive/view/v1'
export const DOMAIN_IDENTITY = 'para-id/v1'

export const IDENTITY_INDEXES = {
  public: 0,
  civic: 1,
  anonymous: 2,
} as const

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

/** H_scalar: SHA-512 interpreted little-endian, reduced mod the group order l. */
export function hashToScalar(...parts: Uint8Array[]): bigint {
  return bytesToNumberLE(sha512(concat(...parts))) % L
}

function u32le(n: number): Uint8Array {
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, n, true)
  return out
}

export interface MasterKeys {
  spendPriv: bigint
  viewPriv: bigint
  spendPub: Uint8Array
}

export function deriveMasterKeys(seed: Uint8Array): MasterKeys {
  if (seed.length !== 32) {
    throw new Error('seed must be exactly 32 bytes')
  }
  const spendPriv = hashToScalar(utf8(DOMAIN_SPEND), seed)
  const viewPriv = hashToScalar(utf8(DOMAIN_VIEW), seed)
  const spendPub = RistrettoPoint.BASE.multiply(spendPriv).toRawBytes()
  return { spendPriv, viewPriv, spendPub }
}

export interface DerivedIdentity {
  index: number
  priv: bigint
  pub: Uint8Array
}

/**
 * identity_i = spend_pub + H(DOMAIN_IDENTITY ‖ view_priv ‖ LE32(i))·G
 *
 * view_priv is encoded as its canonical 32-byte little-endian scalar. The
 * additive tweak means identities are unlinkable to each other and to
 * spend_pub for anyone who does not hold view_priv, while the holder can sign
 * for identity_i with spend_priv + t_i.
 */
export function deriveIdentity(keys: MasterKeys, index: number): DerivedIdentity {
  const tweak = hashToScalar(
    utf8(DOMAIN_IDENTITY),
    numberToBytesLE(keys.viewPriv, 32),
    u32le(index),
  )
  const priv = (keys.spendPriv + tweak) % L
  const pub = RistrettoPoint.BASE.multiply(priv).toRawBytes()
  return { index, priv, pub }
}

export interface DerivationVector {
  seed: string
  spendPriv: string
  viewPriv: string
  spendPub: string
  identities: { index: number; label: string; priv: string; pub: string }[]
}

export function deriveVector(seed: Uint8Array): DerivationVector {
  const keys = deriveMasterKeys(seed)
  return {
    seed: bytesToHex(seed),
    spendPriv: bytesToHex(numberToBytesLE(keys.spendPriv, 32)),
    viewPriv: bytesToHex(numberToBytesLE(keys.viewPriv, 32)),
    spendPub: bytesToHex(keys.spendPub),
    identities: Object.entries(IDENTITY_INDEXES).map(([label, index]) => {
      const id = deriveIdentity(keys, index)
      return {
        index,
        label,
        priv: bytesToHex(numberToBytesLE(id.priv, 32)),
        pub: bytesToHex(id.pub),
      }
    }),
  }
}
