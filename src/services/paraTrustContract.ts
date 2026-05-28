/** The PARA trust contract defines the rules for verifying claims via PARA. */

export type ParaRecordType =
  | 'identity_verification'
  | 'public_figure_attestation'
  | 'party_affiliation'
  | 'age_eligibility'
  | 'backup_coverage'

export type ParaSignatureRequirement = {
  algorithm: 'Ed25519'
  issuerDidRequired: boolean
  issuerKeyIdRequired: boolean
  deviceSignatureRequired: boolean
}

export type ParaFreshnessPolicy = {
  maxStalenessSeconds: number
  requireFreshOnUse: boolean
}

export type ParaRevocationState = 'active' | 'suspended' | 'revoked' | 'expired'

export type ParaFailureState =
  | 'issuer_unreachable'
  | 'signature_invalid'
  | 'credential_expired'
  | 'credential_revoked'
  | 'freshness_exceeded'
  | 'commitment_unknown'
  | 'issuer_not_trusted'

export type ParaTrustContractEntry = {
  recordType: ParaRecordType
  signatureRequirements: ParaSignatureRequirement
  freshnessPolicy: ParaFreshnessPolicy
  allowedRevocationTransitions: Array<[ParaRevocationState, ParaRevocationState]>
  failureStates: ParaFailureState[]
}

export const PARA_TRUST_CONTRACT: Record<ParaRecordType, ParaTrustContractEntry> = {
  identity_verification: {
    recordType: 'identity_verification',
    signatureRequirements: {
      algorithm: 'Ed25519',
      issuerDidRequired: true,
      issuerKeyIdRequired: true,
      deviceSignatureRequired: true,
    },
    freshnessPolicy: { maxStalenessSeconds: 365 * 24 * 60 * 60, requireFreshOnUse: false },
    allowedRevocationTransitions: [
      ['active', 'suspended'],
      ['active', 'revoked'],
      ['active', 'expired'],
      ['suspended', 'active'],
      ['suspended', 'revoked'],
    ],
    failureStates: [
      'issuer_unreachable',
      'signature_invalid',
      'credential_expired',
      'credential_revoked',
      'issuer_not_trusted',
    ],
  },
  public_figure_attestation: {
    recordType: 'public_figure_attestation',
    signatureRequirements: {
      algorithm: 'Ed25519',
      issuerDidRequired: true,
      issuerKeyIdRequired: true,
      deviceSignatureRequired: false,
    },
    freshnessPolicy: { maxStalenessSeconds: 300, requireFreshOnUse: true },
    allowedRevocationTransitions: [
      ['active', 'revoked'],
      ['active', 'expired'],
    ],
    failureStates: [
      'issuer_unreachable',
      'signature_invalid',
      'credential_expired',
      'credential_revoked',
      'freshness_exceeded',
      'issuer_not_trusted',
    ],
  },
  party_affiliation: {
    recordType: 'party_affiliation',
    signatureRequirements: {
      algorithm: 'Ed25519',
      issuerDidRequired: false,
      issuerKeyIdRequired: false,
      deviceSignatureRequired: false,
    },
    freshnessPolicy: { maxStalenessSeconds: 86400, requireFreshOnUse: false },
    allowedRevocationTransitions: [
      ['active', 'revoked'],
      ['active', 'expired'],
    ],
    failureStates: ['issuer_unreachable', 'freshness_exceeded'],
  },
  age_eligibility: {
    recordType: 'age_eligibility',
    signatureRequirements: {
      algorithm: 'Ed25519',
      issuerDidRequired: true,
      issuerKeyIdRequired: true,
      deviceSignatureRequired: false,
    },
    freshnessPolicy: { maxStalenessSeconds: 365 * 24 * 60 * 60, requireFreshOnUse: false },
    allowedRevocationTransitions: [
      ['active', 'revoked'],
      ['active', 'expired'],
    ],
    failureStates: [
      'signature_invalid',
      'credential_expired',
      'credential_revoked',
      'commitment_unknown',
      'issuer_not_trusted',
    ],
  },
  backup_coverage: {
    recordType: 'backup_coverage',
    signatureRequirements: {
      algorithm: 'Ed25519',
      issuerDidRequired: false,
      issuerKeyIdRequired: false,
      deviceSignatureRequired: false,
    },
    freshnessPolicy: { maxStalenessSeconds: 3600, requireFreshOnUse: false },
    allowedRevocationTransitions: [['active', 'expired']],
    failureStates: ['freshness_exceeded'],
  },
}

/** Map internal claim types to PARA trust contract record types. */
export function mapClaimTypeToParaRecordType(claimType: string): ParaRecordType | null {
  switch (claimType) {
    case 'has_para_verification':
    case 'is_verified_public_figure':
      return 'public_figure_attestation'
    case 'has_party_affiliation_match':
    case 'joined_during_founding_period':
    case 'has_continuous_party_membership_30d':
      return 'party_affiliation'
    case 'is_age_eligible':
      return 'age_eligibility'
    case 'has_backup_coverage':
      return 'backup_coverage'
    case 'is_civic_eligible':
      return 'identity_verification'
    default:
      return null
  }
}
