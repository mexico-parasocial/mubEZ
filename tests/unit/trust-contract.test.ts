import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  PARA_TRUST_CONTRACT,
  type ParaRecordType,
  mapClaimTypeToParaRecordType,
} from '../../src/services/paraTrustContract.js'
import {
  validateRevocationTransition,
  checkFreshness,
  diagnoseFailure,
} from '../../src/services/paraTrustEnforcer.js'
import { isValidCommitment, FIELD_MODULUS } from '../../src/services/zkpService.js'

const ALL_RECORD_TYPES: ParaRecordType[] = [
  'identity_verification',
  'public_figure_attestation',
  'party_affiliation',
  'age_eligibility',
  'backup_coverage',
]

describe('PARA trust contract', () => {
  it('covers all ParaRecordType values', () => {
    for (const rt of ALL_RECORD_TYPES) {
      assert.ok(PARA_TRUST_CONTRACT[rt], `Missing contract entry for ${rt}`)
      assert.equal(PARA_TRUST_CONTRACT[rt].recordType, rt)
    }
  })

  it('allows all documented revocation transitions', () => {
    const cases: Array<{
      current: import('../../src/services/paraTrustContract.js').ParaRevocationState
      next: import('../../src/services/paraTrustContract.js').ParaRevocationState
      recordType: ParaRecordType
      expected: boolean
    }> = [
      // identity_verification supports suspended
      { current: 'active', next: 'suspended', recordType: 'identity_verification', expected: true },
      { current: 'active', next: 'revoked', recordType: 'identity_verification', expected: true },
      { current: 'active', next: 'expired', recordType: 'identity_verification', expected: true },
      { current: 'suspended', next: 'active', recordType: 'identity_verification', expected: true },
      { current: 'suspended', next: 'revoked', recordType: 'identity_verification', expected: true },
      { current: 'suspended', next: 'expired', recordType: 'identity_verification', expected: false },
      // public_figure_attestation does not support suspended
      { current: 'active', next: 'suspended', recordType: 'public_figure_attestation', expected: false },
      { current: 'active', next: 'revoked', recordType: 'public_figure_attestation', expected: true },
      // backup_coverage only active -> expired
      { current: 'active', next: 'revoked', recordType: 'backup_coverage', expected: false },
      { current: 'active', next: 'expired', recordType: 'backup_coverage', expected: true },
      // same state is always allowed
      { current: 'active', next: 'active', recordType: 'age_eligibility', expected: true },
    ]

    for (const c of cases) {
      const result = validateRevocationTransition(c.current, c.next, c.recordType)
      assert.equal(result, c.expected, `Transition ${c.current} -> ${c.next} for ${c.recordType} should be ${c.expected}`)
    }
  })

  it('returns correct freshness results per record type', () => {
    const now = new Date().toISOString()
    const oneMinuteAgo = new Date(Date.now() - 60_000).toISOString()
    const oneDayAgo = new Date(Date.now() - 86400_000).toISOString()
    const oneDayAndOneSecondAgo = new Date(Date.now() - 86401_000).toISOString()
    const oneYearAgo = new Date(Date.now() - 365 * 86400_000).toISOString()
    const oneYearAndOneDayAgo = new Date(Date.now() - 366 * 86400_000).toISOString()

    // public_figure_attestation: max 300s
    assert.equal(checkFreshness(now, 'public_figure_attestation').fresh, true)
    assert.equal(checkFreshness(oneMinuteAgo, 'public_figure_attestation').fresh, true)
    assert.equal(checkFreshness(oneDayAgo, 'public_figure_attestation').fresh, false)

    // party_affiliation: max 86400s
    assert.equal(checkFreshness(oneMinuteAgo, 'party_affiliation').fresh, true)
    assert.equal(checkFreshness(oneDayAndOneSecondAgo, 'party_affiliation').fresh, false)

    // identity_verification: max 1 year
    assert.equal(checkFreshness(oneDayAgo, 'identity_verification').fresh, true)
    assert.equal(checkFreshness(oneYearAgo, 'identity_verification').fresh, true)
    assert.equal(checkFreshness(oneYearAndOneDayAgo, 'identity_verification').fresh, false)

    // backup_coverage: max 3600s
    assert.equal(checkFreshness(oneMinuteAgo, 'backup_coverage').fresh, true)
    assert.equal(checkFreshness(oneDayAgo, 'backup_coverage').fresh, false)
  })

  it('diagnoses each failure state correctly', () => {
    assert.equal(
      diagnoseFailure({ recordType: 'public_figure_attestation', issuerReachable: false }),
      'issuer_unreachable',
    )
    assert.equal(
      diagnoseFailure({ recordType: 'age_eligibility', signatureValid: false }),
      'signature_invalid',
    )
    assert.equal(
      diagnoseFailure({ recordType: 'age_eligibility', credentialExpired: true }),
      'credential_expired',
    )
    assert.equal(
      diagnoseFailure({ recordType: 'age_eligibility', credentialRevoked: true }),
      'credential_revoked',
    )
    assert.equal(
      diagnoseFailure({ recordType: 'age_eligibility', commitmentKnown: false }),
      'commitment_unknown',
    )
    assert.equal(
      diagnoseFailure({ recordType: 'age_eligibility', issuerTrusted: false }),
      'issuer_not_trusted',
    )
    assert.equal(
      diagnoseFailure({
        recordType: 'public_figure_attestation',
        evaluatedAt: new Date(Date.now() - 400_000).toISOString(),
      }),
      'freshness_exceeded',
    )
    assert.equal(
      diagnoseFailure({ recordType: 'backup_coverage', issuerReachable: false }),
      null,
    )
  })

  it('maps claim types to record types', () => {
    assert.equal(mapClaimTypeToParaRecordType('is_verified_public_figure'), 'public_figure_attestation')
    assert.equal(mapClaimTypeToParaRecordType('has_party_affiliation_match'), 'party_affiliation')
    assert.equal(mapClaimTypeToParaRecordType('is_age_eligible'), 'age_eligibility')
    assert.equal(mapClaimTypeToParaRecordType('has_backup_coverage'), 'backup_coverage')
    assert.equal(mapClaimTypeToParaRecordType('is_civic_eligible'), 'identity_verification')
    assert.equal(mapClaimTypeToParaRecordType('unknown_claim'), null)
  })

  it('validates BN254 commitment bounds', () => {
    assert.equal(isValidCommitment('0'), false)
    assert.equal(isValidCommitment('1'), true)
    assert.equal(isValidCommitment(String(FIELD_MODULUS - 1n)), true)
    assert.equal(isValidCommitment(String(FIELD_MODULUS)), false)
    assert.equal(isValidCommitment(String(FIELD_MODULUS + 1n)), false)
    assert.equal(isValidCommitment('not-a-number'), false)
  })
})
