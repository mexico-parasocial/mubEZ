import {
  PARA_TRUST_CONTRACT,
  type ParaFailureState,
  type ParaRecordType,
  type ParaRevocationState,
} from './paraTrustContract.js'

export class ParaTrustViolationError extends Error {
  constructor(
    message: string,
    public readonly failureState: ParaFailureState,
  ) {
    super(message)
    this.name = 'ParaTrustViolationError'
  }
}

export function validateRevocationTransition(
  current: ParaRevocationState,
  next: ParaRevocationState,
  recordType: ParaRecordType,
): boolean {
  if (current === next) return true
  const entry = PARA_TRUST_CONTRACT[recordType]
  if (!entry) return false
  const allowed = entry.allowedRevocationTransitions
  return allowed.some(([from, to]) => from === current && to === next)
}

export function checkFreshness(
  evaluatedAt: string,
  recordType: ParaRecordType,
): { fresh: boolean; stalenessSeconds: number } {
  const entry = PARA_TRUST_CONTRACT[recordType]
  if (!entry) {
    return { fresh: true, stalenessSeconds: 0 }
  }
  const max = entry.freshnessPolicy.maxStalenessSeconds
  const evaluated = new Date(evaluatedAt).getTime()
  const now = Date.now()
  const stalenessSeconds = Math.floor((now - evaluated) / 1000)
  return { fresh: stalenessSeconds <= max, stalenessSeconds }
}

export function diagnoseFailure(context: {
  recordType: ParaRecordType
  issuerReachable?: boolean
  signatureValid?: boolean
  credentialExpired?: boolean
  credentialRevoked?: boolean
  commitmentKnown?: boolean
  issuerTrusted?: boolean
  evaluatedAt?: string
}): ParaFailureState | null {
  const entry = PARA_TRUST_CONTRACT[context.recordType]
  if (!entry) return null

  const failures: ParaFailureState[] = []

  if (context.issuerReachable === false && entry.failureStates.includes('issuer_unreachable')) {
    failures.push('issuer_unreachable')
  }
  if (context.signatureValid === false && entry.failureStates.includes('signature_invalid')) {
    failures.push('signature_invalid')
  }
  if (context.credentialExpired === true && entry.failureStates.includes('credential_expired')) {
    failures.push('credential_expired')
  }
  if (context.credentialRevoked === true && entry.failureStates.includes('credential_revoked')) {
    failures.push('credential_revoked')
  }
  if (context.commitmentKnown === false && entry.failureStates.includes('commitment_unknown')) {
    failures.push('commitment_unknown')
  }
  if (context.issuerTrusted === false && entry.failureStates.includes('issuer_not_trusted')) {
    failures.push('issuer_not_trusted')
  }
  if (context.evaluatedAt) {
    const { fresh } = checkFreshness(context.evaluatedAt, context.recordType)
    if (!fresh && entry.failureStates.includes('freshness_exceeded')) {
      failures.push('freshness_exceeded')
    }
  }

  return failures[0] ?? null
}
