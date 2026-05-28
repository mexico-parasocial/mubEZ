import env from '#start/env'
import { Features, isFeatureEnabled } from './features.js'
import { PROOF_BROKER_CLAIM_TYPES } from '../types/index.js'
import { mapClaimTypeToParaRecordType } from './paraTrustContract.js'
import type { ProofBrokerClaimType, ProofBrokerParaProviderStatus } from '../types/index.js'

export type ParaClaimVerificationResult = {
  claimType: ProofBrokerClaimType
  subject: string
  disposition: 'verified' | 'bounded' | 'review-needed' | 'unavailable' | 'not-verified'
  outcome: 'verified' | 'not-verified' | 'matched' | 'mismatched' | 'bounded' | null
  requestedValue: string | null
  statement: string
  reference: string | null
  notes: string
  evaluatedAt: string
  contractRecordType: ReturnType<typeof mapClaimTypeToParaRecordType>
}

function nowIso() {
  return new Date().toISOString()
}

export async function resolveParaProviderStatus(): Promise<ProofBrokerParaProviderStatus> {
  const paraApiBaseUrl = env.get('PARA_API_BASE_URL')
  const hasApi = Boolean(paraApiBaseUrl)
  // WARNING: Local PARA fallback is for demo/development only.
  // In production, unavailability of the live PARA API should result in
  // degraded service, not automatic fallback to local deterministic logic.
  const localFallbackEnabled = isFeatureEnabled(Features.LocalParaFallbackEnable)

  if (hasApi) {
    try {
      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), env.get('PARA_API_TIMEOUT_MS'))
      const res = await fetch(`${paraApiBaseUrl}/xrpc/app.bsky.actor.getProfile?actor=para.verifier`, {
        signal: controller.signal,
      })
      clearTimeout(timeout)

      if (res.ok) {
        return {
          providerId: 'para.identity',
          displayName: 'PARA Trust MX',
          availability: 'online',
          compatibility: 'ready',
          policyRecord: 'com.para.identity',
          compatibilityRecord: 'app.bsky.graph.verification',
          lastSyncAt: nowIso(),
          supportedClaims: [...PROOF_BROKER_CLAIM_TYPES],
          notes: 'PARA API reachable. Real-time verification enabled.',
        }
      }
    } catch {
      // fall through to degraded
    }
  }

  return {
    providerId: 'para.identity',
    displayName: 'PARA Trust MX',
    availability: hasApi ? 'degraded' : localFallbackEnabled ? 'online' : 'offline',
    compatibility: 'needs-review',
    policyRecord: 'com.para.identity',
    compatibilityRecord: 'app.bsky.graph.verification',
    lastSyncAt: nowIso(),
    supportedClaims: [...PROOF_BROKER_CLAIM_TYPES],
    notes: hasApi
      ? 'PARA API is configured but unreachable. Operating in degraded mode.'
      : localFallbackEnabled
        ? 'No PARA_API_BASE_URL configured. Using local seed resolution.'
        : 'No PARA_API_BASE_URL configured and local PARA fallback is disabled.',
  }
}

export async function verifyParaClaim(input: {
  subject: string
  claimType: ProofBrokerClaimType
  requestedValue?: string
  audienceAppId: string
  audienceAppName: string
  reason: string
}): Promise<ParaClaimVerificationResult> {
  const paraApiBaseUrl = env.get('PARA_API_BASE_URL')
  const hasApi = Boolean(paraApiBaseUrl)
  let apiUnavailable = false

  if (hasApi) {
    try {
      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), env.get('PARA_API_TIMEOUT_MS'))
      const res = await fetch(`${paraApiBaseUrl}/xrpc/app.bsky.actor.getProfile?actor=${encodeURIComponent(input.subject)}`, {
        signal: controller.signal,
      })
      clearTimeout(timeout)

      if (res.ok) {
        const profile = (await res.json()) as Record<string, unknown>
        const verified = Boolean(profile?.verification)

        if (input.claimType === 'has_para_verification' || input.claimType === 'is_verified_public_figure') {
          if (verified) {
            return {
              claimType: input.claimType,
              subject: input.subject,
              disposition: 'verified',
              outcome: 'verified',
              requestedValue: input.requestedValue ?? null,
              statement: `PARA API confirms ${input.claimType} for ${input.subject}.`,
              reference: (profile.did as string) ?? null,
              notes: 'Resolved via live PARA API.',
              evaluatedAt: nowIso(),
              contractRecordType: mapClaimTypeToParaRecordType(input.claimType),
            }
          }
        }
      }
    } catch {
      apiUnavailable = true
    }
  }

  if (!isFeatureEnabled(Features.LocalParaFallbackEnable)) {
    return {
      claimType: input.claimType,
      subject: input.subject,
      disposition: apiUnavailable ? 'unavailable' : 'not-verified',
      outcome: apiUnavailable ? null : 'not-verified',
      requestedValue: input.requestedValue ?? null,
      statement: apiUnavailable
        ? 'PARA API is unavailable and local fallback is disabled.'
        : `No live PARA verification record found for ${input.claimType}.`,
      reference: null,
      notes: 'Local PARA fallback disabled by GrowthBook gate.',
      evaluatedAt: nowIso(),
      contractRecordType: mapClaimTypeToParaRecordType(input.claimType),
    }
  }

  // Local fallback (simplified from POC seed logic)
  const isDemoVerified = input.subject.toLowerCase().includes('demo') || input.subject.toLowerCase().includes('test')

  if (input.claimType === 'has_party_affiliation_match') {
    return {
      claimType: input.claimType,
      subject: input.subject,
      disposition: 'bounded',
      outcome: 'bounded',
      requestedValue: input.requestedValue ?? 'independent',
      statement: `Bounded party affiliation match: ${input.requestedValue ?? 'independent'}`,
      reference: `local:party:${input.subject}`,
      notes: 'Resolved via local fallback (no PARA API).',
      evaluatedAt: nowIso(),
      contractRecordType: mapClaimTypeToParaRecordType(input.claimType),
    }
  }

  if (
    input.claimType === 'joined_during_founding_period' ||
    input.claimType === 'has_continuous_party_membership_30d'
  ) {
    const party = input.requestedValue ?? 'party'
    return {
      claimType: input.claimType,
      subject: input.subject,
      disposition: 'bounded',
      outcome: 'bounded',
      requestedValue: party,
      statement:
        input.claimType === 'joined_during_founding_period'
          ? `Bounded party tenure proof: joined during founding period for ${party}.`
          : `Bounded party tenure proof: continuous membership is at least 30 days for ${party}.`,
      reference: `local:party-tenure:${input.subject}`,
      notes: 'Resolved via local fallback without disclosing an exact join date.',
      evaluatedAt: nowIso(),
      contractRecordType: mapClaimTypeToParaRecordType(input.claimType),
    }
  }

  if (isDemoVerified) {
    return {
      claimType: input.claimType,
      subject: input.subject,
      disposition: 'verified',
      outcome: 'verified',
      requestedValue: input.requestedValue ?? null,
      statement: `Local verification confirms ${input.claimType} for demo subject.`,
      reference: `local:${input.subject}`,
      notes: 'Resolved via local fallback (demo mode).',
      evaluatedAt: nowIso(),
      contractRecordType: mapClaimTypeToParaRecordType(input.claimType),
    }
  }

  return {
    claimType: input.claimType,
    subject: input.subject,
    disposition: 'not-verified',
    outcome: 'not-verified',
    requestedValue: input.requestedValue ?? null,
    statement: `No verification record found for ${input.claimType}.`,
    reference: null,
    notes: 'Local fallback returned no match.',
    evaluatedAt: nowIso(),
    contractRecordType: mapClaimTypeToParaRecordType(input.claimType),
  }
}
