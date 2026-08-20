import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { hexToBytes, bytesToHex } from '@noble/curves/abstract/utils'
import {
  encodeAssertion as refEncode,
  signAssertion,
  sr25519PublicKey,
  encodeSecretScalar,
} from '../helpers/identitySignature.js'
import {
  verifyIdentityAssertion,
  encodeAssertion,
} from '../../src/services/identitySignature.js'

const vectorsFile = JSON.parse(
  readFileSync(new URL('../../docs/identity-signature-vectors.json', import.meta.url), 'utf8'),
)

const scalarOf = (privHexLE: string): bigint =>
  BigInt('0x' + bytesToHex(hexToBytes(privHexLE).slice().reverse()))

const NOW = new Date('2026-08-24T12:00:30.000Z')

describe('identity signature vectors', () => {
  it('reproduces the canonical encoding byte for byte', () => {
    // This is the specification. An implementation that encodes differently
    // signs different bytes and will never interoperate.
    for (const v of vectorsFile.vectors) {
      assert.equal(new TextDecoder().decode(refEncode(v.assertion)), v.encoded)
      assert.equal(new TextDecoder().decode(encodeAssertion(v.assertion)), v.encoded)
    }
  })

  it('derives the sr25519 public key from the identity scalar', () => {
    // The property the whole scheme rests on: identity_pub IS the sr25519
    // public key. If the cofactor shift were wrong this diverges silently.
    for (const v of vectorsFile.vectors) {
      assert.equal(bytesToHex(sr25519PublicKey(scalarOf(v.privLE))), v.sr25519PublicKey)
      // and it must equal identity_pub from the derivation spec
      assert.equal(v.sr25519PublicKey, v.assertion.identityPub)
    }
  })

  it('verifies every published signature', () => {
    for (const v of vectorsFile.vectors) {
      assert.ok(
        verifyIdentityAssertion(
          { assertion: v.assertion, signature: v.signature },
          {
            purpose: v.purpose,
            audience: v.audience,
            challenge: v.assertion.challenge,
            now: NOW,
          },
        ),
        `vector ${v.seed}/${v.label}/${v.purpose} failed to verify`,
      )
    }
  })
})

describe('verifier rejections', () => {
  const v = vectorsFile.vectors[0]
  const base = {
    purpose: v.purpose,
    audience: v.audience,
    challenge: v.assertion.challenge,
    now: NOW,
  }
  const signed = { assertion: v.assertion, signature: v.signature }

  it('rejects a purpose it was not asked for', () => {
    // Both consumers sign with the same key. Without this, a registration
    // signature would log someone into Matrix.
    const other = vectorsFile.vectors.find(
      (x: any) => x.purpose === 'mubez-registration',
    )
    assert.ok(
      verifyIdentityAssertion(
        { assertion: other.assertion, signature: other.signature },
        { ...base, purpose: 'mubez-registration', audience: other.audience },
      ),
    )
    assert.equal(
      verifyIdentityAssertion(
        { assertion: other.assertion, signature: other.signature },
        { ...base, purpose: 'matrix-login', audience: other.audience },
      ),
      false,
    )
  })

  it('rejects a mismatched audience or challenge', () => {
    assert.equal(verifyIdentityAssertion(signed, { ...base, audience: 'evil' }), false)
    assert.equal(verifyIdentityAssertion(signed, { ...base, challenge: 'other' }), false)
  })

  it('rejects a stale or future-dated assertion', () => {
    assert.equal(
      verifyIdentityAssertion(signed, { ...base, now: new Date('2026-08-24T13:00:00.000Z') }),
      false,
      'an hour-old assertion must not verify',
    )
    assert.equal(
      verifyIdentityAssertion(signed, { ...base, now: new Date('2026-08-24T11:00:00.000Z') }),
      false,
      'an assertion from the future must not verify',
    )
  })

  it('rejects a tampered assertion', () => {
    for (const patch of [
      { type: 'para.identity.pop.v2' },
      { identityPub: '00'.repeat(32) },
      { signedAt: '2026-08-24T12:00:01.000Z' },
    ]) {
      assert.equal(
        verifyIdentityAssertion(
          { assertion: { ...v.assertion, ...patch } as any, signature: v.signature },
          base,
        ),
        false,
      )
    }
  })

  it('returns false rather than throwing on hostile input', () => {
    // This runs on a public endpoint. sr25519's verify() raises on a malformed
    // point and a null body raises before any field is read; unguarded, both
    // are a 500 instead of an auth failure.
    const junk: unknown[] = [
      null, undefined, '', 'zz', '00', 'ff'.repeat(64), 'gg'.repeat(64), 123, {}, [],
    ]
    for (const sig of junk) {
      for (const pub of junk) {
        assert.equal(
          verifyIdentityAssertion(
            {
              assertion: { ...v.assertion, identityPub: String(pub) },
              signature: String(sig),
            } as any,
            base,
          ),
          false,
        )
      }
    }
    for (const shape of [
      null, undefined, 'str', 42, [], {},
      { assertion: null, signature: v.signature },
      { assertion: v.assertion },
      { assertion: v.assertion, signature: 1 },
    ]) {
      assert.equal(verifyIdentityAssertion(shape as any, base), false)
    }
  })
})

describe('scalar encoding', () => {
  it('rejects out-of-range scalars', () => {
    const L = 2n ** 252n + 27742317777372353535851937790883648493n
    assert.throws(() => encodeSecretScalar(0n), /out of range/)
    assert.throws(() => encodeSecretScalar(L), /out of range/)
  })

  it('is lossless across the range', () => {
    const L = 2n ** 252n + 27742317777372353535851937790883648493n
    const decode = (b: Uint8Array) =>
      b.reduceRight((acc, byte) => (acc << 8n) | BigInt(byte), 0n) >> 3n
    for (const x of [1n, 2n, 255n, 2n ** 251n, L - 1n]) {
      assert.equal(decode(encodeSecretScalar(x)), x)
    }
  })

  it('produces a fresh signature each time (synthetic nonce)', () => {
    const scalar = scalarOf(vectorsFile.vectors[0].privLE)
    const a = signAssertion(scalar, vectorsFile.vectors[0].assertion)
    const b = signAssertion(scalar, vectorsFile.vectors[0].assertion)
    assert.notEqual(a, b, 'signatures must not be deterministic')
  })
})
