import { randomUUID } from 'node:crypto'
import { getDb } from '../db/connection.js'
import { hydrateSession } from './sessionService.js'
import { verifyClaim } from './trustPolicy.js'
import type {
  ProofBrokerClaimSpec,
  ProofBrokerGrantApproveInput,
  ProofBrokerGrantMutationResult,
  ProofBrokerGrantRequestInput,
  ProofBrokerGrantRevokeInput,
  ProofBrokerProofArtifact,
  ProofBrokerSession,
} from '../types/index.js'

function nowIso() {
  return new Date().toISOString()
}

export function requestGrant(sessionId: string, input: ProofBrokerGrantRequestInput): ProofBrokerGrantMutationResult {
  const db = getDb()
  const id = `grant-${randomUUID()}`
  const now = nowIso()

  db.prepare(`
    INSERT INTO grants (id, request_id, session_id, app_id, app_name, app_kind, surface, requested_claims_json, proof_mode, status, reason, requested_at, expires_at, issuer_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    `request-${randomUUID()}`,
    sessionId,
    input.appId,
    input.appName,
    input.appKind,
    input.surface,
    JSON.stringify(input.requestedClaims),
    input.proofMode,
    'pending',
    input.reason,
    now,
    input.expiresAt ?? null,
    'm8.broker'
  )

  db.prepare(`
    INSERT INTO ledger (session_id, action, target_type, target_id, detail_json)
    VALUES (?, ?, ?, ?, ?)
  `).run(sessionId, 'Requested', 'grant', id, JSON.stringify({ reason: input.reason, appId: input.appId }))

  const session = hydrateSession(sessionId)
  const grant = session.grants.find((g) => g.id === id)!
  return { session, grant, proofs: [] }
}

export function approveGrant(sessionId: string, input: ProofBrokerGrantApproveInput): ProofBrokerGrantMutationResult {
  const db = getDb()
  const now = nowIso()

  const grantRow = db.prepare('SELECT * FROM grants WHERE id = ? AND session_id = ?').get(input.grantId, sessionId) as Record<string, unknown> | undefined
  if (!grantRow) throw new Error('Grant not found')
  if (grantRow.status !== 'pending') throw new Error('Grant is not pending')

  const requestedClaims: ProofBrokerClaimSpec[] = JSON.parse(grantRow.requested_claims_json as string)
  const proofArtifacts: ProofBrokerProofArtifact[] = []

  for (const claim of requestedClaims) {
    const verification = verifyClaim({
      sessionId,
      claimType: claim.type,
      requestedValue: claim.requestedValue,
      audienceAppId: grantRow.app_id as string,
      audienceAppName: grantRow.app_name as string,
      surface: grantRow.surface as ProofBrokerSession['activeSurfaceId'],
      proofMode: claim.disclosure,
      verifierId: 'm8.broker',
      reason: grantRow.reason as string,
    })

    const proofId = `proof-${randomUUID()}`
    db.prepare(`
      INSERT INTO proof_artifacts (id, session_id, grant_id, request_id, claim_type, requested_value, outcome, statement, proof_mode, issuer_id, verifier_id, audience_app_id, audience_app_name, surface, reference, status, issued_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      proofId,
      sessionId,
      input.grantId,
      grantRow.request_id,
      claim.type,
      claim.requestedValue ?? null,
      verification.outcome,
      verification.statement,
      claim.disclosure,
      'm8.broker',
      'm8.broker',
      grantRow.app_id,
      grantRow.app_name,
      grantRow.surface,
      verification.reference ?? '',
      'active',
      now,
      null
    )

    proofArtifacts.push({
      id: proofId,
      grantId: input.grantId,
      requestId: grantRow.request_id as string,
      claimType: claim.type,
      requestedValue: claim.requestedValue ?? null,
      outcome: verification.outcome,
      statement: verification.statement,
      proofMode: claim.disclosure,
      issuerId: 'm8.broker',
      verifierId: 'm8.broker',
      audienceAppId: grantRow.app_id as string,
      audienceAppName: grantRow.app_name as string,
      surface: grantRow.surface as ProofBrokerSession['activeSurfaceId'],
      reference: verification.reference ?? '',
      status: 'active',
      issuedAt: now,
      lastUsedAt: null,
      expiresAt: null,
      revokedAt: null,
    })
  }

  const artifactIds = proofArtifacts.map((p) => p.id)
  db.prepare(`
    UPDATE grants SET status = ?, issued_at = ?, proof_artifact_ids_json = ?, review_note = ? WHERE id = ?
  `).run('approved', now, JSON.stringify(artifactIds), input.reviewNote ?? null, input.grantId)

  db.prepare(`
    INSERT INTO ledger (session_id, action, target_type, target_id, detail_json)
    VALUES (?, ?, ?, ?, ?)
  `).run(sessionId, 'Approved', 'grant', input.grantId, JSON.stringify({ reviewNote: input.reviewNote, proofCount: proofArtifacts.length }))

  const session = hydrateSession(sessionId)
  const grant = session.grants.find((g) => g.id === input.grantId)!
  return { session, grant, proofs: proofArtifacts }
}

export function revokeGrant(sessionId: string, input: ProofBrokerGrantRevokeInput): ProofBrokerGrantMutationResult {
  const db = getDb()
  const now = nowIso()

  const grantRow = db.prepare('SELECT * FROM grants WHERE id = ? AND session_id = ?').get(input.grantId, sessionId) as Record<string, unknown> | undefined
  if (!grantRow) throw new Error('Grant not found')

  db.prepare('UPDATE grants SET status = ? WHERE id = ?').run('revoked', input.grantId)
  db.prepare('UPDATE proof_artifacts SET status = ?, revoked_at = ? WHERE grant_id = ?').run('revoked', now, input.grantId)

  db.prepare(`
    INSERT INTO ledger (session_id, action, target_type, target_id, detail_json)
    VALUES (?, ?, ?, ?, ?)
  `).run(sessionId, 'Revoked', 'grant', input.grantId, JSON.stringify({ reason: input.reason }))

  const session = hydrateSession(sessionId)
  const grant = session.grants.find((g) => g.id === input.grantId)!
  return { session, grant, proofs: session.proofs.filter((p) => p.grantId === input.grantId) }
}
