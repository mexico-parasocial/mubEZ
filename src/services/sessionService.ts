import { createHash, randomUUID } from 'node:crypto'
import env from '#start/env'
import { getDb } from '../db/connection.js'
import { resolveHandleToDid, resolvePdsEndpoint } from './didResolver.js'
import { PROOF_BROKER_CLAIM_TYPES } from '../types/index.js'
import { scopeForSurface } from './scopePolicy.js'
import type {
  ProofBrokerSession,
  ProofBrokerSessionStartInput,
  ProofBrokerSessionStartResponse,
  ProofBrokerSurfaceId,
  ProofBrokerDisclosureMode,
  ProofBrokerGrantStatus,
  ProofBrokerProofOutcome,
  ProofBrokerVerifierId,
  ProofBrokerProofStatus,
} from '../types/index.js'

function nowIso() {
  return new Date().toISOString()
}

export async function createSession(input: ProofBrokerSessionStartInput): Promise<ProofBrokerSessionStartResponse> {
  const db = getDb()
  const identifier = input.identifier.trim()
  const oauthScope = scopeForSurface(input.surface)

  // Real ATProto handle/DID resolution
  let did: string
  let handle: string

  if (identifier.startsWith('did:')) {
    did = identifier
    handle = identifier
  } else {
    const cleanHandle = identifier.replace(/^@/, '')
    const resolvedDid = await resolveHandleToDid(cleanHandle)

    if (resolvedDid) {
      did = resolvedDid
      handle = cleanHandle
    } else if (env.get('NODE_ENV') === 'development' || env.get('NODE_ENV') === 'test') {
      // Fallback for dev/test: synthesize a DID so tests still work
      did = `did:plc:${Buffer.from(cleanHandle).toString('base64url').slice(0, 24)}`
      handle = cleanHandle
    } else {
      throw new Error(`Could not resolve handle: ${identifier}`)
    }
  }

  // Resolve PDS endpoint from DID document
  const pdsEndpoint = await resolvePdsEndpoint(did)
  const authServer = pdsEndpoint ?? env.get('PDS_URL')

  const sessionId = randomUUID()
  const now = nowIso()

  const pdsSafety = {
    state: 'Enroll now' as const,
    detail: 'No PDS backup configured for this identity.',
    source: 'm8.broker',
    lastBackup: now,
  }

  db.prepare(`
    INSERT INTO sessions (session_id, did, handle, display_name, authorization_server, authenticated_at, pds_safety_json, active_persona_id, active_surface_id, oauth_scope, created_at, updated_at, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
  `).run(sessionId, did, handle, handle, authServer, now, JSON.stringify(pdsSafety), 'orbit', 'public', oauthScope, now, now)

  const paraStatus = {
    providerId: 'para.identity' as const,
    displayName: 'PARA Trust MX',
    availability: 'online' as const,
    compatibility: 'needs-review' as const,
    policyRecord: 'com.para.identity' as const,
    compatibilityRecord: 'app.bsky.graph.verification' as const,
    lastSyncAt: now,
    supportedClaims: [...PROOF_BROKER_CLAIM_TYPES],
    notes: 'PARA provider initialized. Awaiting first sync.',
  }

  db.prepare(`
    INSERT INTO provider_status (session_id, provider_id, display_name, availability, compatibility, policy_record, compatibility_record, last_sync_at, supported_claims_json, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(sessionId, paraStatus.providerId, paraStatus.displayName, paraStatus.availability, paraStatus.compatibility, paraStatus.policyRecord, paraStatus.compatibilityRecord, paraStatus.lastSyncAt, JSON.stringify(paraStatus.supportedClaims), paraStatus.notes)

  // Seed default claim requests
  const defaultClaims = [
    { id: `claim-${randomUUID()}`, type: 'has_para_verification' as const },
    { id: `claim-${randomUUID()}`, type: 'is_verified_public_figure' as const },
  ]

  for (const claim of defaultClaims) {
    db.prepare(`
      INSERT INTO claim_requests (id, session_id, app_id, app_name, app_kind, surface, requested_claims_json, proof_mode, status, reason, requested_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(claim.id, sessionId, 'm8.console', 'M8 Console', 'Broker', 'public', JSON.stringify([{ type: claim.type, disclosure: 'proof-only' }]), 'proof-only', 'pending', 'Auto-seeded on session creation.', now)
  }

  const attempt = {
    sessionId,
    did,
    handle,
    authorizationServer: authServer,
    authUrl: `${authServer}/oauth/authorize?client_id=m8.broker&request_uri=${encodeURIComponent(`${env.get('SERVICE_URL')}/v1/sessions/oauth/callback`)}`,
    phaseLabel: 'Awaiting authorization',
    startedAt: now,
    resolvedAt: now,
  }

  const session = hydrateSession(sessionId)
  return { attempt, session }
}

export function hydrateSession(sessionId: string): ProofBrokerSession {
  const db = getDb()
  const row = db.prepare('SELECT * FROM sessions WHERE session_id = ?').get(sessionId) as Record<string, unknown> | undefined
  if (!row) throw new Error('Session not found')

  const claimRequestRows = db.prepare('SELECT * FROM claim_requests WHERE session_id = ?').all(sessionId) as Record<string, unknown>[]
  const grantRows = db.prepare('SELECT * FROM grants WHERE session_id = ?').all(sessionId) as Record<string, unknown>[]
  const proofRows = db.prepare('SELECT * FROM proof_artifacts WHERE session_id = ?').all(sessionId) as Record<string, unknown>[]
  const providerRow = db.prepare('SELECT * FROM provider_status WHERE session_id = ?').get(sessionId) as Record<string, unknown> | undefined

  return buildSession(row, claimRequestRows, grantRows, proofRows, providerRow)
}

export function buildSession(
  row: Record<string, unknown>,
  claimRequestRows: Record<string, unknown>[],
  grantRows: Record<string, unknown>[],
  proofRows: Record<string, unknown>[],
  providerRow?: Record<string, unknown>
): ProofBrokerSession {
  const sessionId = row.session_id as string
  const now = nowIso()

  const pdsSafety = JSON.parse((row.pds_safety_json as string) || '{}')
  if (!pdsSafety.state) {
    pdsSafety.state = 'Enroll now'
    pdsSafety.detail = 'No PDS backup configured for this identity.'
    pdsSafety.source = 'm8.broker'
    pdsSafety.lastBackup = now
  }

  const personas = [
    {
      id: 'orbit', name: 'Orbit', handle: row.handle as string, role: 'Social face', summary: 'Default public-facing persona.',
      activeSurface: 'public' as const, surfaceStates: { public: 'Live' as const, civic: 'Limited' as const, dating: 'Muted' as const },
    },
    {
      id: 'signal', name: 'Signal', handle: `${row.handle}.civic`, role: 'Civic proof profile', summary: 'Persona for civic and government interactions.',
      activeSurface: 'civic' as const, surfaceStates: { public: 'Limited' as const, civic: 'Live' as const, dating: 'Muted' as const },
    },
    {
      id: 'spark', name: 'Spark', handle: `${row.handle}.private`, role: 'Selective dating profile', summary: 'Persona for selective disclosure contexts.',
      activeSurface: 'dating' as const, surfaceStates: { public: 'Muted' as const, civic: 'Muted' as const, dating: 'Live' as const },
    },
  ]

  const surfaces = [
    { id: 'public' as const, label: 'Public', audience: 'Everyone', status: 'Live' as const, defaultDisclosureMode: 'proof-only' as const },
    { id: 'civic' as const, label: 'Civic', audience: 'Verified institutions', status: 'Limited' as const, defaultDisclosureMode: 'proof-only' as const },
    { id: 'dating' as const, label: 'Dating', audience: 'Matched profiles', status: 'Muted' as const, defaultDisclosureMode: 'proof-only' as const },
  ]

  const claimRequests = claimRequestRows.map((r) => ({
    id: r.id as string,
    appId: r.app_id as string,
    appName: r.app_name as string,
    appKind: r.app_kind as ProofBrokerSession['claimRequests'][number]['appKind'],
    surface: r.surface as ProofBrokerSurfaceId,
    requestedClaims: JSON.parse(r.requested_claims_json as string),
    proofMode: r.proof_mode as ProofBrokerDisclosureMode,
    status: r.status as ProofBrokerGrantStatus,
    reason: r.reason as string,
    requestedAt: r.requested_at as string,
    issuedAt: r.issued_at as string | null,
    lastUsedAt: r.last_used_at as string | null,
    expiresAt: r.expires_at as string | null,
    grantId: r.grant_id as string | null,
  }))

  const grants = grantRows.map((r) => ({
    id: r.id as string,
    requestId: r.request_id as string,
    appId: r.app_id as string,
    appName: r.app_name as string,
    appKind: r.app_kind as ProofBrokerSession['grants'][number]['appKind'],
    surface: r.surface as ProofBrokerSurfaceId,
    requestedClaims: JSON.parse(r.requested_claims_json as string),
    proofMode: r.proof_mode as ProofBrokerDisclosureMode,
    status: r.status as ProofBrokerGrantStatus,
    reason: r.reason as string,
    requestedAt: r.requested_at as string,
    issuedAt: r.issued_at as string | null,
    lastUsedAt: r.last_used_at as string | null,
    expiresAt: r.expires_at as string | null,
    proofArtifactIds: JSON.parse(r.proof_artifact_ids_json as string || '[]'),
    issuerId: r.issuer_id as ProofBrokerSession['grants'][number]['issuerId'],
    reviewNote: r.review_note as string | null,
  }))

  const proofs = proofRows.map((r) => ({
    id: r.id as string,
    grantId: r.grant_id as string,
    requestId: r.request_id as string,
    claimType: r.claim_type as ProofBrokerSession['proofs'][number]['claimType'],
    requestedValue: r.requested_value as string | null,
    outcome: r.outcome as ProofBrokerProofOutcome,
    statement: r.statement as string,
    proofMode: r.proof_mode as ProofBrokerDisclosureMode,
    issuerId: r.issuer_id as ProofBrokerVerifierId,
    verifierId: r.verifier_id as ProofBrokerVerifierId,
    audienceAppId: r.audience_app_id as string,
    audienceAppName: r.audience_app_name as string,
    surface: r.surface as ProofBrokerSurfaceId,
    reference: r.reference as string,
    status: r.status as ProofBrokerProofStatus,
    issuedAt: r.issued_at as string,
    lastUsedAt: r.last_used_at as string | null,
    expiresAt: r.expires_at as string | null,
    revokedAt: r.revoked_at as string | null,
  }))

  const paraStatus: ProofBrokerSession['paraStatus'] = providerRow
    ? {
        providerId: providerRow.provider_id as 'para.identity',
        displayName: providerRow.display_name as string,
        availability: providerRow.availability as ProofBrokerSession['paraStatus']['availability'],
        compatibility: providerRow.compatibility as ProofBrokerSession['paraStatus']['compatibility'],
        policyRecord: providerRow.policy_record as 'com.para.identity',
        compatibilityRecord: providerRow.compatibility_record as 'app.bsky.graph.verification',
        lastSyncAt: providerRow.last_sync_at as string,
        supportedClaims: JSON.parse(providerRow.supported_claims_json as string),
        notes: providerRow.notes as string,
      }
    : {
        providerId: 'para.identity',
        displayName: 'PARA Trust MX',
        availability: 'offline',
        compatibility: 'needs-review',
        policyRecord: 'com.para.identity',
        compatibilityRecord: 'app.bsky.graph.verification',
        lastSyncAt: now,
        supportedClaims: [],
        notes: 'Provider status unavailable.',
      }

  return {
    sessionId,
    brokerMode: 'local',
    did: row.did as string,
    handle: row.handle as string,
    displayName: row.display_name as string,
    authorizationServer: row.authorization_server as string,
    authenticatedAt: row.authenticated_at as string,
    status: (row.status as ProofBrokerSession['status'] | undefined) ?? 'active',
    oauthScope: (row.oauth_scope as string) || 'atproto',
    pdsSafety,
    personas,
    surfaces,
    claimRequests,
    grants,
    proofs,
    paraStatus,
    activePersonaId: row.active_persona_id as string,
    activeSurfaceId: row.active_surface_id as ProofBrokerSurfaceId,
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
  }
}

// JWT helpers
export function hashRefreshToken(token: string): string {
  return createHash('sha256').update(token).digest('hex')
}
