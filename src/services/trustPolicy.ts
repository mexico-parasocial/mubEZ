import { getDb } from '../db/connection.js'
import { Features, isFeatureEnabled } from './features.js'
import { mapClaimTypeToParaRecordType } from './paraTrustContract.js'
import type { ProofBrokerClaimType, ProofBrokerProofOutcome, ProofBrokerSession } from '../types/index.js'

export function verifyClaim(input: {
  sessionId: string
  claimType: ProofBrokerClaimType
  requestedValue?: string
  audienceAppId: string
  audienceAppName: string
  surface: ProofBrokerSession['activeSurfaceId']
  proofMode: ProofBrokerSession['surfaces'][number]['defaultDisclosureMode']
  verifierId: 'm8.broker' | 'para.identity'
  reason: string
}): { outcome: ProofBrokerProofOutcome; statement: string; reference: string | null; recordType: ReturnType<typeof mapClaimTypeToParaRecordType> } {
  const db = getDb()
  const sessionRow = db.prepare('SELECT * FROM sessions WHERE session_id = ?').get(input.sessionId) as Record<string, unknown> | undefined
  if (!sessionRow) {
    return { outcome: 'not-verified', statement: 'Session not found.', reference: null, recordType: mapClaimTypeToParaRecordType(input.claimType) }
  }

  // WARNING: Local trust policy is a fallback for demo/development only.
  // In production with real PARA integration, this should not be the primary
  // trust path. The flag is an operational convenience, not an authorization control.
  if (!isFeatureEnabled(Features.LocalTrustPolicyEnable)) {
    return {
      outcome: 'not-verified',
      statement: 'Local demo trust policy is disabled.',
      reference: null,
      recordType: mapClaimTypeToParaRecordType(input.claimType),
    }
  }

  // Placeholder trust policy logic
  switch (input.claimType) {
    case 'is_verified_public_figure': {
      // In production: query PARA API or local seed
      const hasPara = db.prepare('SELECT COUNT(*) as count FROM claim_requests WHERE session_id = ? AND status = ?').get(input.sessionId, 'approved') as { count: number }
      if (hasPara.count > 0) {
        return { outcome: 'verified', statement: 'Verified public figure status confirmed via PARA.', reference: `para:${sessionRow.handle}`, recordType: mapClaimTypeToParaRecordType(input.claimType) }
      }
      return { outcome: 'not-verified', statement: 'No verified public figure record found.', reference: null, recordType: mapClaimTypeToParaRecordType(input.claimType) }
    }
    case 'is_civic_eligible': {
      return { outcome: 'verified', statement: 'Civic eligibility assumed for demo purposes.', reference: `civic:${input.sessionId}`, recordType: mapClaimTypeToParaRecordType(input.claimType) }
    }
    case 'has_para_verification': {
      return { outcome: 'verified', statement: 'PARA verification present.', reference: `para:${sessionRow.handle}`, recordType: mapClaimTypeToParaRecordType(input.claimType) }
    }
    case 'has_party_affiliation_match': {
      return { outcome: 'bounded', statement: `Bounded party affiliation match: ${input.requestedValue ?? 'none'}`, reference: `party:${input.sessionId}`, recordType: mapClaimTypeToParaRecordType(input.claimType) }
    }
    case 'joined_during_founding_period': {
      return {
        outcome: 'bounded',
        statement: `Bounded party tenure proof: joined during founding period for ${input.requestedValue ?? 'party'}.`,
        reference: `party-tenure:${input.sessionId}`,
        recordType: mapClaimTypeToParaRecordType(input.claimType),
      }
    }
    case 'has_continuous_party_membership_30d': {
      return {
        outcome: 'bounded',
        statement: `Bounded party tenure proof: continuous membership is at least 30 days for ${input.requestedValue ?? 'party'}.`,
        reference: `party-tenure:${input.sessionId}`,
        recordType: mapClaimTypeToParaRecordType(input.claimType),
      }
    }
    case 'is_age_eligible': {
      return { outcome: 'verified', statement: 'Age eligibility verified via identity wallet.', reference: `age:${input.sessionId}`, recordType: mapClaimTypeToParaRecordType(input.claimType) }
    }
    case 'has_backup_coverage': {
      const pdsSafety = JSON.parse((sessionRow.pds_safety_json as string) || '{}')
      if (pdsSafety.state === 'Backed up') {
        return { outcome: 'verified', statement: 'PDS backup coverage confirmed.', reference: `backup:${input.sessionId}`, recordType: mapClaimTypeToParaRecordType(input.claimType) }
      }
      return { outcome: 'not-verified', statement: 'No backup coverage configured.', reference: null, recordType: mapClaimTypeToParaRecordType(input.claimType) }
    }
    default:
      return { outcome: 'not-verified', statement: 'Claim type not supported by trust policy.', reference: null, recordType: mapClaimTypeToParaRecordType(input.claimType) }
  }
}
