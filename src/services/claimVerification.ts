import { getDb } from '../db/connection.js'
import { Features, isFeatureEnabled } from './features.js'
import { verifyParaClaim } from './paraProvider.js'
import { hasActiveIneCommitment } from './proofOfHumanity.js'
import { verifyClaim as verifyClaimLocalDemo } from './trustPolicy.js'
import { mapClaimTypeToParaRecordType } from './paraTrustContract.js'
import type { ProofBrokerClaimType, ProofBrokerProofOutcome, ProofBrokerSession } from '../types/index.js'

export type VerifyClaimInput = {
  sessionId: string
  claimType: ProofBrokerClaimType
  requestedValue?: string
  audienceAppId: string
  audienceAppName: string
  surface: ProofBrokerSession['activeSurfaceId']
  proofMode: ProofBrokerSession['surfaces'][number]['defaultDisclosureMode']
  verifierId: 'm8.broker' | 'para.identity'
  reason: string
}

export type VerifyClaimResult = {
  outcome: ProofBrokerProofOutcome
  statement: string
  reference: string | null
  recordType: ReturnType<typeof mapClaimTypeToParaRecordType>
  verifierId: 'm8.broker' | 'para.identity'
}

/**
 * PARA is the authoritative source for these claims
 * (PARA_INTEGRATION_CONTRACT.md). Verified live via the PARA network.
 */
const PARA_AUTHORITATIVE = new Set<ProofBrokerClaimType>([
  'is_verified_public_figure',
  'has_para_verification',
  'has_party_affiliation_match',
  'joined_during_founding_period',
  'has_continuous_party_membership_30d',
])

/**
 * M8 derives these from its own proof-of-humanity (active INE ZK
 * commitment), not from any demo assumption.
 */
const M8_POH_DERIVED = new Set<ProofBrokerClaimType>([
  'is_age_eligible',
  'is_civic_eligible',
])

function notVerified(statement: string, claimType: ProofBrokerClaimType): VerifyClaimResult {
  return {
    outcome: 'not-verified',
    statement,
    reference: null,
    recordType: mapClaimTypeToParaRecordType(claimType),
    verifierId: 'm8.broker',
  }
}

/**
 * Demo-only escape hatch: the local trust policy (blanket "verified" for
 * development demos) may only answer when its explicit flag is on. In
 * production the flag is off, so the honest upstream result always stands
 * and nothing silently downgrades to a positive demo result.
 */
function demoFallback(input: VerifyClaimInput, honestStatement: string): VerifyClaimResult {
  if (isFeatureEnabled(Features.LocalTrustPolicyEnable)) {
    const demo = verifyClaimLocalDemo(input)
    return {
      outcome: demo.outcome,
      statement: `${demo.statement} (demo trust policy)`,
      reference: demo.reference,
      recordType: demo.recordType,
      verifierId: 'm8.broker',
    }
  }
  return notVerified(honestStatement, input.claimType)
}

/**
 * Routes claim verification to its authoritative source:
 * - PARA-authoritative claims → live PARA network (with DID binding per the
 *   integration contract's session-mismatch rule).
 * - M8-derived claims → real proof-of-humanity check.
 * - Everything else → local trust policy (which itself fails closed in prod).
 */
export async function verifyClaimRouted(input: VerifyClaimInput): Promise<VerifyClaimResult> {
  const db = getDb()
  const sessionRow = db
    .prepare('SELECT session_id, did, handle FROM sessions WHERE session_id = ?')
    .get(input.sessionId) as { session_id: string; did: string; handle: string } | undefined
  if (!sessionRow) {
    return notVerified('Session not found.', input.claimType)
  }

  if (PARA_AUTHORITATIVE.has(input.claimType)) {
    const live = await verifyParaClaim({
      subject: sessionRow.did,
      claimType: input.claimType,
      requestedValue: input.requestedValue,
      audienceAppId: input.audienceAppId,
      audienceAppName: input.audienceAppName,
      reason: input.reason,
    })

    if (live.disposition === 'verified' || live.disposition === 'bounded') {
      // Contract: a PARA result for a different DID must be rejected. Only
      // live API results carry a DID reference; local fallback references
      // are namespaced (`local:*`) and not subject to this check.
      if (
        live.reference?.startsWith('did:') &&
        live.reference !== sessionRow.did
      ) {
        return notVerified(
          `PARA verification subject mismatch (issuer_not_trusted): result is bound to ${live.reference}, expected ${sessionRow.did}.`,
          input.claimType,
        )
      }
      return {
        outcome: live.outcome ?? 'not-verified',
        statement: live.statement,
        reference: live.reference,
        recordType: live.contractRecordType,
        verifierId: 'para.identity',
      }
    }

    // Live path said not-verified or unavailable. Only an explicitly
    // flagged demo environment may soften that answer.
    return demoFallback(input, live.statement)
  }

  if (M8_POH_DERIVED.has(input.claimType)) {
    if (hasActiveIneCommitment(input.sessionId)) {
      return {
        outcome: 'verified',
        statement:
          input.claimType === 'is_age_eligible'
            ? 'Age eligibility derived from an active INE ZK commitment.'
            : 'Civic eligibility derived from an active INE ZK commitment.',
        reference: `ine-commitment:${input.sessionId}`,
        recordType: mapClaimTypeToParaRecordType(input.claimType),
        verifierId: 'm8.broker',
      }
    }
    return demoFallback(
      input,
      'No active INE identity commitment for this session.',
    )
  }

  // Remaining types (e.g. has_backup_coverage) keep the existing local
  // trust-policy logic, which already fails closed when its flag is off.
  const local = verifyClaimLocalDemo(input)
  return { ...local, verifierId: 'm8.broker' }
}
