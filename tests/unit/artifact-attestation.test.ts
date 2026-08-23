import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { verify } from '@scure/sr25519'
import { hexToBytes } from '@noble/curves/abstract/utils'

import {
  encodeArtifactRow,
  signArtifactRow,
  signWithSeed,
  artifactIssuerPublicKey,
  type ArtifactRow,
} from '../../src/services/artifactAttestation.js'

// Fixed 32-byte test seed; the published vector in docs/ uses the same one.
export const VECTOR_SEED =
  '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'

const baseRow: ArtifactRow = {
  id: 'proof-vector-1',
  grant_id: 'grant-42',
  request_id: 'req-7',
  claim_type: 'humanity',
  requested_value: null,
  outcome: 'granted',
  statement: 'The holder demonstrated proof of humanity.',
  proof_mode: 'proof-only',
  issuer_id: 'm8.broker',
  verifier_id: 'm8.broker',
  audience_app_id: 'app.para.console',
  surface: 'public',
  issued_at: '2026-08-22T00:00:00.000Z',
  expires_at: null,
}

function cloneRow(overrides: Partial<ArtifactRow> = {}): ArtifactRow {
  return { ...baseRow, ...overrides }
}

describe('artifact attestation (para.artifact.v1)', () => {
  it('produces well-formed attestations and fresh entropy per signature', () => {
    const a = signWithSeed(VECTOR_SEED, cloneRow())
    const b = signWithSeed(VECTOR_SEED, cloneRow())
    assert.equal(a.attestation.alg, 'para.artifact.v1')
    assert.match(a.attestation.issuerPub, /^[0-9a-f]{64}$/)
    assert.match(a.attestation.signature, /^[0-9a-f]{128}$/)
    // Schnorrkel: nonce entropy is fresh per signature, so two signatures
    // over the same row differ — the stored attestation is THE artifact's.
    assert.notEqual(a.attestation.signature, b.attestation.signature)
    // both still verify against the same key
    for (const sig of [a.attestation.signature, b.attestation.signature]) {
      assert.equal(
        verify(
          encodeArtifactRow(cloneRow()),
          hexToBytes(sig),
          hexToBytes(a.attestation.issuerPub),
        ),
        true,
      )
    }
  })

  it('is reproducible when nonce entropy is pinned (vector mode)', () => {
    const r1 = signWithSeed(VECTOR_SEED, cloneRow(), '00'.repeat(32))
    const r2 = signWithSeed(VECTOR_SEED, cloneRow(), '00'.repeat(32))
    assert.deepEqual(r1.attestation.signature, r2.attestation.signature)
  })

  it('verifies with sr25519 over the canonical encoding', () => {
    const { attestation } = signWithSeed(VECTOR_SEED, cloneRow())
    const ok = verify(
      encodeArtifactRow(cloneRow()),
      hexToBytes(attestation.signature),
      hexToBytes(attestation.issuerPub),
    )
    assert.equal(ok, true)
  })

  it('different seeds produce different issuers and signatures', () => {
    const otherSeed =
      '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'
    const a = signWithSeed(VECTOR_SEED, cloneRow())
    const b = signWithSeed(otherSeed, cloneRow())
    assert.notEqual(a.attestation.issuerPub, b.attestation.issuerPub)
    assert.notEqual(a.attestation.signature, b.attestation.signature)
  })

  // Every field that changes the meaning of the artifact must be covered by
  // the canonical encoding: editing it after signing must break verification.
  const meaningfulFields: (keyof ArtifactRow)[] = [
    'id',
    'grant_id',
    'request_id',
    'claim_type',
    'outcome',
    'statement',
    'proof_mode',
    'issuer_id',
    'verifier_id',
    'audience_app_id',
    'surface',
    'issued_at',
  ]

  for (const field of meaningfulFields) {
    it(`tampering ${field} breaks the signature`, () => {
      const { attestation } = signWithSeed(VECTOR_SEED, cloneRow())
      const value = baseRow[field]
      const tampered = cloneRow({
        [field]: typeof value === 'string' ? `${value}x` : 'tampered',
      } as Partial<ArtifactRow>)
      const ok = verify(
        encodeArtifactRow(tampered),
        hexToBytes(attestation.signature),
        hexToBytes(attestation.issuerPub),
      )
      assert.equal(ok, false, `${field} was not covered by the signature`)
    })
  }

  it('requested_value and expires_at are covered when present', () => {
    const withOptionals = cloneRow({
      requested_value: '18+',
      expires_at: '2027-01-01T00:00:00.000Z',
    })
    const { attestation } = signWithSeed(VECTOR_SEED, withOptionals)
    const tamperedValue = cloneRow({
      requested_value: '21+',
      expires_at: '2027-01-01T00:00:00.000Z',
    })
    const tamperedExpiry = cloneRow({
      requested_value: '18+',
      expires_at: '2099-01-01T00:00:00.000Z',
    })
    for (const tampered of [tamperedValue, tamperedExpiry]) {
      assert.equal(
        verify(
          encodeArtifactRow(tampered),
          hexToBytes(attestation.signature),
          hexToBytes(attestation.issuerPub),
        ),
        false,
      )
    }
  })

  it('signArtifactRow returns null without a configured seed', () => {
    // No M8_ARTIFACT_ISSUER_SEED in the test environment.
    assert.equal(artifactIssuerPublicKey(), null)
    assert.equal(signArtifactRow(cloneRow()), null)
  })

  it('canonical encoding is the documented 15-line newline join', () => {
    const { canonical } = signWithSeed(VECTOR_SEED, cloneRow())
    const lines = canonical.split('\n')
    assert.equal(lines.length, 15)
    assert.equal(lines[0], 'para.artifact.v1')
    assert.equal(lines[5], '') // requested_value null encodes as empty
    assert.equal(lines[14], '') // expires_at null encodes as empty
  })
})
