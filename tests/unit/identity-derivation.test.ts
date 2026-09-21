import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { RistrettoPoint } from '@noble/curves/ed25519'
import { hexToBytes, bytesToHex, bytesToNumberLE, numberToBytesLE } from '@noble/curves/abstract/utils'
import {
  deriveMasterKeys,
  deriveIdentity,
  deriveVector,
  hashToScalar,
  DOMAIN_IDENTITY,
  IDENTITY_INDEXES,
} from '../helpers/identityDerivation.js'

const vectorsFile = JSON.parse(
  readFileSync(new URL('../../docs/identity-derivation-vectors.json', import.meta.url), 'utf8'),
)

describe('identity derivation reference implementation', () => {
  it('reproduces the published test vectors byte for byte', () => {
    for (const expected of vectorsFile.vectors) {
      const actual = deriveVector(hexToBytes(expected.seed))
      assert.deepEqual(actual, expected)
    }
  })

  it('derives identity pubs additively from spend_pub without spend_priv', () => {
    // The property iM8 and mubEZ both rely on: identity_pub_i can be computed
    // from (spend_pub, view_priv) alone, and it matches BASE * identity_priv_i.
    for (const vector of vectorsFile.vectors) {
      const spendPub = RistrettoPoint.fromHex(vector.spendPub)
      const viewPriv = bytesToNumberLE(hexToBytes(vector.viewPriv))
      for (const identity of vector.identities) {
        const tweak = hashToScalar(
          new TextEncoder().encode(DOMAIN_IDENTITY),
          numberToBytesLE(viewPriv, 32),
          new Uint8Array(new Uint32Array([identity.index]).buffer),
        )
        const fromPub = spendPub.add(RistrettoPoint.BASE.multiply(tweak))
        assert.equal(bytesToHex(fromPub.toRawBytes()), identity.pub)
      }
    }
  })

  it('produces unlinkable identities: distinct across indexes and seeds', () => {
    const a = deriveMasterKeys(hexToBytes('11'.repeat(32)))
    const b = deriveMasterKeys(hexToBytes('22'.repeat(32)))
    const pubs = new Set<string>()
    for (const keys of [a, b]) {
      for (const index of Object.values(IDENTITY_INDEXES)) {
        pubs.add(bytesToHex(deriveIdentity(keys, index).pub))
      }
      pubs.add(bytesToHex(keys.spendPub))
    }
    assert.equal(pubs.size, 8)
  })

  it('separates spend and view keys by domain', () => {
    const keys = deriveMasterKeys(hexToBytes('33'.repeat(32)))
    assert.notEqual(keys.spendPriv, keys.viewPriv)
  })

  it('rejects seeds that are not exactly 32 bytes', () => {
    assert.throws(() => deriveMasterKeys(hexToBytes('aa'.repeat(31))), /32 bytes/)
    assert.throws(() => deriveMasterKeys(hexToBytes('aa'.repeat(33))), /32 bytes/)
  })
})
