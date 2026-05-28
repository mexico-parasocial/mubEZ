import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { getDb } from '../db/connection.js'
import { proofBrokerClaimLabel, type ProofBrokerClaimType, type ProofBrokerSurfaceId } from '../types/index.js'
import { assertTrustedDevice, getDeviceTrustSummary, type DeviceTrustSummary } from './deviceTrustService.js'

export type AnonymousIdentityStatus = 'active' | 'archived'
export type AnonymousDmPolicy = 'off' | 'requests' | 'para-verified'
export type AnonymousGermMode = 'germ-card-link' | 'm8-relay-pending-germ'
export type AnonymousDmSenderRequirement = 'none' | 'para-verified'

export interface PublicProofBadge {
  claimType: ProofBrokerClaimType
  label: string
  outcome: string
  issuedAt: string
}

export interface AnonymousIdentityCard {
  id: string
  displayName: string
  avatarSeed: string
  surface: ProofBrokerSurfaceId
  communityUri: string | null
  status: AnonymousIdentityStatus
  deviceTrust: DeviceTrustSummary
  proofBadges: PublicProofBadge[]
  posts: AnonymousIdentityPost[]
  germ: AnonymousGermConnection | null
  createdAt: string
  updatedAt: string
  archivedAt: string | null
}

export interface AnonymousIdentityPost {
  id: string
  identityId: string
  postUri: string
  communityUri: string | null
  postType: string
  proofArtifactIds: string[]
  dmPolicy: AnonymousDmPolicy
  stats: AnonymousPostStats
  createdAt: string
  updatedAt: string
}

export interface AnonymousPostStats {
  replyCount: number
  repostCount: number
  likeCount: number
  quoteCount: number
  threadCount: number
  syncedAt: string | null
}

export interface AnonymousGermConnection {
  id: string
  identityId: string
  provider: 'germ'
  providerRef: string
  contactUrl: string
  mode: AnonymousGermMode
  status: 'active' | 'revoked'
  createdAt: string
  updatedAt: string
  revokedAt: string | null
}

export interface AnonymousGermContactPayload {
  provider: 'germ'
  label: 'Private reply via Germ DM'
  contactUrl: string
  mode: AnonymousGermMode
  proofBadges: PublicProofBadge[]
  dmPolicy: Exclude<AnonymousDmPolicy, 'off'>
  senderRequirement: AnonymousDmSenderRequirement
}

export type AnonymousPublicContact = { dmEnabled: false } | (
  Omit<AnonymousGermContactPayload, 'contactUrl'> & {
    dmEnabled: true
    contactUrl?: string
  }
)

export type AnonymousContactEligibility = { eligible: false; reason: string; code: string } | (
  { eligible: true } & AnonymousGermContactPayload
)

const PUBLIC_BADGE_CLAIMS = new Set<ProofBrokerClaimType>([
  'is_civic_eligible',
  'has_para_verification',
  'joined_during_founding_period',
  'has_continuous_party_membership_30d',
  'is_age_eligible',
])

export function listAnonymousIdentities(sessionId: string): AnonymousIdentityCard[] {
  const db = getDb()
  ensureDefaultAnonymousIdentity(sessionId)
  const rows = db.prepare(`
    SELECT * FROM anonymous_identities
    WHERE session_id = ?
    ORDER BY status ASC, updated_at DESC, created_at DESC
  `).all(sessionId) as Record<string, unknown>[]

  return rows.map((row) => hydrateIdentityCard(sessionId, row))
}

export function createAnonymousIdentity(sessionId: string, input: {
  displayName?: string
  surface?: ProofBrokerSurfaceId
  communityUri?: string | null
}): AnonymousIdentityCard {
  const db = getDb()
  const now = new Date().toISOString()
  const secret = randomBytes(32).toString('hex')
  const id = `anon-identity-${randomUUID()}`
  const displayName = input.displayName?.trim() || `Ciudadano #${secret.slice(0, 6).toUpperCase()}`
  const avatarSeed = randomBytes(16).toString('hex')

  db.prepare(`
    INSERT INTO anonymous_identities
      (id, session_id, display_name, avatar_seed, nullifier_secret_hash, surface, community_uri, status, device_trust_state, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    sessionId,
    displayName,
    avatarSeed,
    createHash('sha256').update(secret).digest('hex'),
    input.surface ?? 'civic',
    input.communityUri ?? null,
    'active',
    getDeviceTrustSummary(sessionId).status,
    now,
    now,
  )
  writeLedger(sessionId, 'AnonymousIdentityCreated', 'anonymous_identity', id, {
    surface: input.surface ?? 'civic',
    communityUri: input.communityUri ?? null,
  })
  return requireAnonymousIdentity(sessionId, id)
}

export function updateAnonymousIdentity(sessionId: string, identityId: string, input: {
  displayName?: string
  status?: AnonymousIdentityStatus
}): AnonymousIdentityCard {
  requireAnonymousIdentityRow(sessionId, identityId)
  const db = getDb()
  const existing = requireAnonymousIdentity(sessionId, identityId)
  const status = input.status ?? existing.status
  const archivedAt = status === 'archived' && !existing.archivedAt ? new Date().toISOString() : existing.archivedAt

  db.prepare(`
    UPDATE anonymous_identities
    SET display_name = ?, status = ?, archived_at = ?, updated_at = ?
    WHERE id = ? AND session_id = ?
  `).run(
    input.displayName?.trim() || existing.displayName,
    status,
    archivedAt,
    new Date().toISOString(),
    identityId,
    sessionId,
  )
  writeLedger(sessionId, 'AnonymousIdentityUpdated', 'anonymous_identity', identityId, { status })
  return requireAnonymousIdentity(sessionId, identityId)
}

export function linkAnonymousPost(sessionId: string, input: {
  identityId?: string
  postUri: string
  communityUri?: string | null
  postType?: string
  stats?: Partial<Omit<AnonymousPostStats, 'syncedAt'>>
}): AnonymousIdentityPost {
  const db = getDb()
  const identity = input.identityId
    ? requireAnonymousIdentity(sessionId, input.identityId)
    : ensureDefaultAnonymousIdentity(sessionId)
  if (identity.status === 'archived') {
    throw appError('Archived anonymous identity cannot be used', 409, 'ANONYMOUS_IDENTITY_ARCHIVED')
  }

  const now = new Date().toISOString()
  const existing = db.prepare('SELECT * FROM anonymous_identity_posts WHERE post_uri = ?').get(input.postUri) as Record<string, unknown> | undefined
  if (existing) {
    if (!ownsPost(sessionId, existing)) {
      throw appError('Anonymous post belongs to another session', 403, 'ANONYMOUS_POST_FORBIDDEN')
    }
    return mapPost(existing)
  }

  const proofIds = listPublicProofBadges(sessionId).map((badge) => badge.id)
  const id = `anon-post-${randomUUID()}`
  const stats = normalizeStats(input.stats)
  db.prepare(`
    INSERT INTO anonymous_identity_posts
      (id, identity_id, post_uri, community_uri, post_type, proof_artifact_ids_json, dm_policy, reply_count, repost_count, like_count, quote_count, thread_count, stats_synced_at, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    identity.id,
    input.postUri,
    input.communityUri ?? null,
    input.postType ?? 'post',
    JSON.stringify(proofIds),
    'off',
    stats.replyCount,
    stats.repostCount,
    stats.likeCount,
    stats.quoteCount,
    stats.threadCount,
    stats.syncedAt,
    now,
    now,
  )
  writeLedger(sessionId, 'AnonymousPostLinked', 'anonymous_identity_post', id, {
    identityId: identity.id,
    postUri: input.postUri,
  })
  return requireAnonymousPost(sessionId, id)
}

export function updateAnonymousPostStats(sessionId: string, postId: string, statsInput: Partial<Omit<AnonymousPostStats, 'syncedAt'>>): AnonymousIdentityPost {
  const post = requireAnonymousPost(sessionId, postId)
  const stats = normalizeStats(statsInput, post.stats)
  const db = getDb()
  db.prepare(`
    UPDATE anonymous_identity_posts
    SET reply_count = ?, repost_count = ?, like_count = ?, quote_count = ?, thread_count = ?, stats_synced_at = ?, updated_at = ?
    WHERE id = ?
  `).run(
    stats.replyCount,
    stats.repostCount,
    stats.likeCount,
    stats.quoteCount,
    stats.threadCount,
    stats.syncedAt,
    new Date().toISOString(),
    postId,
  )
  writeLedger(sessionId, 'AnonymousPostStatsUpdated', 'anonymous_identity_post', postId, {
    replyCount: stats.replyCount,
    repostCount: stats.repostCount,
    likeCount: stats.likeCount,
    quoteCount: stats.quoteCount,
    threadCount: stats.threadCount,
  })
  return requireAnonymousPost(sessionId, postId)
}

export function updateAnonymousPostDmPolicy(sessionId: string, postId: string, dmPolicy: AnonymousDmPolicy): AnonymousIdentityPost {
  const post = requireAnonymousPost(sessionId, postId)
  const identity = requireAnonymousIdentity(sessionId, post.identityId)
  if (identity.status === 'archived') {
    throw appError('Archived anonymous identity cannot receive private replies', 409, 'ANONYMOUS_IDENTITY_ARCHIVED')
  }

  if (dmPolicy !== 'off') {
    assertTrustedDevice(sessionId, 'EnableAnonymousPrivateReplies')
    const germ = getActiveGermConnection(identity.id)
    if (!germ) {
      throw appError('Germ contact URL must be linked before enabling private replies', 409, 'GERM_CONTACT_REQUIRED')
    }
  }

  const db = getDb()
  db.prepare(`
    UPDATE anonymous_identity_posts SET dm_policy = ?, updated_at = ?
    WHERE id = ?
  `).run(dmPolicy, new Date().toISOString(), postId)
  writeLedger(sessionId, 'AnonymousDmPolicyUpdated', 'anonymous_identity_post', postId, { dmPolicy })
  return requireAnonymousPost(sessionId, postId)
}

export function linkGermContact(sessionId: string, identityId: string, input: {
  contactUrl: string
  providerRef?: string
  mode?: AnonymousGermMode
}): AnonymousGermConnection {
  assertTrustedDevice(sessionId, 'LinkAnonymousGermContact')
  const identity = requireAnonymousIdentity(sessionId, identityId)
  if (identity.status === 'archived') {
    throw appError('Archived anonymous identity cannot link Germ', 409, 'ANONYMOUS_IDENTITY_ARCHIVED')
  }

  const session = getSessionIdentity(sessionId)
  const url = new URL(input.contactUrl)
  if (url.toString().includes(session.did)) {
    throw appError('Anonymous Germ contact URL must not include the author DID', 400, 'ANONYMOUS_GERM_DID_LEAK')
  }

  const db = getDb()
  const now = new Date().toISOString()
  const existing = getGermConnection(identityId)
  const id = existing?.id ?? `anon-germ-${randomUUID()}`
  db.prepare(`
    INSERT INTO anonymous_dm_connections
      (id, identity_id, provider, provider_ref, contact_url, mode, status, created_at, updated_at, revoked_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      provider_ref = excluded.provider_ref,
      contact_url = excluded.contact_url,
      mode = excluded.mode,
      status = excluded.status,
      updated_at = excluded.updated_at,
      revoked_at = excluded.revoked_at
  `).run(
    id,
    identityId,
    'germ',
    input.providerRef ?? '',
    url.toString(),
    input.mode ?? 'germ-card-link',
    'active',
    existing?.createdAt ?? now,
    now,
    null,
  )

  writeLedger(sessionId, 'AnonymousGermLinked', 'anonymous_identity', identityId, {
    provider: 'germ',
    mode: input.mode ?? 'germ-card-link',
  })
  return getActiveGermConnection(identityId)!
}

export function unlinkGermContact(sessionId: string, identityId: string): AnonymousGermConnection | null {
  requireAnonymousIdentity(sessionId, identityId)
  const germ = getActiveGermConnection(identityId)
  if (!germ) return null
  const now = new Date().toISOString()
  const db = getDb()
  db.prepare(`
    UPDATE anonymous_dm_connections SET status = ?, revoked_at = ?, updated_at = ?
    WHERE id = ?
  `).run('revoked', now, now, germ.id)
  db.prepare(`
    UPDATE anonymous_identity_posts SET dm_policy = ?, updated_at = ?
    WHERE identity_id = ?
  `).run('off', now, identityId)
  writeLedger(sessionId, 'AnonymousGermUnlinked', 'anonymous_identity', identityId, { provider: 'germ' })
  return { ...germ, status: 'revoked', revokedAt: now, updatedAt: now }
}

export function getAnonymousPublicContact(postUri: string): AnonymousPublicContact {
  const contact = resolveAnonymousContact(postUri)
  if (!contact) {
    return { dmEnabled: false }
  }

  const payload: AnonymousPublicContact = {
    dmEnabled: true,
    ...contact,
  }
  if (contact.senderRequirement !== 'none') {
    delete payload.contactUrl
  }
  return payload
}

export function getAnonymousContactEligibility(sessionId: string, postUri: string): AnonymousContactEligibility {
  const contact = resolveAnonymousContact(postUri)
  if (!contact) {
    return {
      eligible: false,
      reason: 'Anonymous post is not accepting Germ DMs.',
      code: 'ANONYMOUS_DM_UNAVAILABLE',
    }
  }

  if (contact.senderRequirement === 'para-verified' && !hasActiveParaVerification(sessionId)) {
    return {
      eligible: false,
      reason: 'Only PARA-verified users can send Germ DMs to this anonymous profile.',
      code: 'PARA_VERIFICATION_REQUIRED',
    }
  }

  return {
    eligible: true,
    ...contact,
  }
}

export function requireAnonymousIdentity(sessionId: string, identityId: string): AnonymousIdentityCard {
  const row = requireAnonymousIdentityRow(sessionId, identityId)
  return hydrateIdentityCard(sessionId, row)
}

function ensureDefaultAnonymousIdentity(sessionId: string): AnonymousIdentityCard {
  const db = getDb()
  const existing = db.prepare(`
    SELECT * FROM anonymous_identities
    WHERE session_id = ?
    ORDER BY created_at ASC
    LIMIT 1
  `).get(sessionId) as Record<string, unknown> | undefined
  if (existing) return hydrateIdentityCard(sessionId, existing)

  const legacy = db.prepare(`
    SELECT id, display_name, avatar_seed, nullifier_secret, created_at
    FROM anonymous_profiles
    WHERE session_id = ?
  `).get(sessionId) as { id: string; display_name: string; avatar_seed: string; nullifier_secret: string; created_at: string } | undefined

  if (legacy) {
    const now = new Date().toISOString()
    db.prepare(`
      INSERT INTO anonymous_identities
        (id, session_id, display_name, avatar_seed, nullifier_secret_hash, surface, status, device_trust_state, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      `anon-identity-${legacy.id}`,
      sessionId,
      legacy.display_name,
      legacy.avatar_seed,
      legacy.nullifier_secret,
      'civic',
      'active',
      getDeviceTrustSummary(sessionId).status,
      legacy.created_at,
      now,
    )
    return requireAnonymousIdentity(sessionId, `anon-identity-${legacy.id}`)
  }

  return createAnonymousIdentity(sessionId, {})
}

function hydrateIdentityCard(sessionId: string, row: Record<string, unknown>): AnonymousIdentityCard {
  const id = row.id as string
  const db = getDb()
  const posts = db.prepare(`
    SELECT * FROM anonymous_identity_posts WHERE identity_id = ? ORDER BY created_at DESC
  `).all(id) as Record<string, unknown>[]

  return {
    id,
    displayName: row.display_name as string,
    avatarSeed: row.avatar_seed as string,
    surface: row.surface as ProofBrokerSurfaceId,
    communityUri: row.community_uri as string | null,
    status: row.status as AnonymousIdentityStatus,
    deviceTrust: getDeviceTrustSummary(sessionId),
    proofBadges: listPublicProofBadges(sessionId),
    posts: posts.map(mapPost),
    germ: getActiveGermConnection(id),
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
    archivedAt: row.archived_at as string | null,
  }
}

function requireAnonymousIdentityRow(sessionId: string, identityId: string): Record<string, unknown> {
  const db = getDb()
  const row = db.prepare('SELECT * FROM anonymous_identities WHERE id = ? AND session_id = ?').get(identityId, sessionId) as Record<string, unknown> | undefined
  if (!row) throw appError('Anonymous identity not found', 404, 'ANONYMOUS_IDENTITY_NOT_FOUND')
  return row
}

function requireAnonymousPost(sessionId: string, postId: string): AnonymousIdentityPost {
  const db = getDb()
  const row = db.prepare(`
    SELECT p.*
    FROM anonymous_identity_posts p
    JOIN anonymous_identities i ON i.id = p.identity_id
    WHERE p.id = ? AND i.session_id = ?
  `).get(postId, sessionId) as Record<string, unknown> | undefined
  if (!row) throw appError('Anonymous post not found', 404, 'ANONYMOUS_POST_NOT_FOUND')
  return mapPost(row)
}

function ownsPost(sessionId: string, postRow: Record<string, unknown>) {
  const db = getDb()
  const row = db.prepare('SELECT session_id FROM anonymous_identities WHERE id = ?').get(postRow.identity_id as string) as { session_id: string } | undefined
  return row?.session_id === sessionId
}

function getGermConnection(identityId: string): AnonymousGermConnection | null {
  const db = getDb()
  const row = db.prepare(`
    SELECT * FROM anonymous_dm_connections
    WHERE identity_id = ? AND provider = 'germ'
    ORDER BY updated_at DESC
    LIMIT 1
  `).get(identityId) as Record<string, unknown> | undefined
  return row ? mapGerm(row) : null
}

function getActiveGermConnection(identityId: string): AnonymousGermConnection | null {
  const germ = getGermConnection(identityId)
  return germ?.status === 'active' ? germ : null
}

function resolveAnonymousContact(postUri: string): AnonymousGermContactPayload | null {
  const db = getDb()
  const post = db.prepare(`
    SELECT p.*, i.session_id, i.status AS identity_status
    FROM anonymous_identity_posts p
    JOIN anonymous_identities i ON i.id = p.identity_id
    WHERE p.post_uri = ?
  `).get(postUri) as Record<string, unknown> | undefined

  if (!post || post.dm_policy === 'off' || post.identity_status !== 'active') {
    return null
  }

  const dmPolicy = post.dm_policy as AnonymousDmPolicy
  const germ = getActiveGermConnection(post.identity_id as string)
  if (!germ || dmPolicy === 'off') return null

  return {
    provider: 'germ',
    label: 'Private reply via Germ DM',
    contactUrl: germ.contactUrl,
    mode: germ.mode,
    proofBadges: listPublicProofBadges(post.session_id as string),
    dmPolicy,
    senderRequirement: dmPolicy === 'para-verified' ? 'para-verified' : 'none',
  }
}

function hasActiveParaVerification(sessionId: string): boolean {
  const db = getDb()
  const row = db.prepare(`
    SELECT 1
    FROM proof_artifacts
    WHERE session_id = ?
      AND claim_type = 'has_para_verification'
      AND status = 'active'
      AND outcome = 'verified'
    LIMIT 1
  `).get(sessionId) as { 1: number } | undefined
  return Boolean(row)
}

function listPublicProofBadges(sessionId: string): Array<PublicProofBadge & { id: string }> {
  const db = getDb()
  const rows = db.prepare(`
    SELECT id, claim_type, outcome, issued_at
    FROM proof_artifacts
    WHERE session_id = ? AND status = 'active'
    ORDER BY issued_at DESC
  `).all(sessionId) as { id: string; claim_type: ProofBrokerClaimType; outcome: string; issued_at: string }[]

  return rows
    .filter((row) => PUBLIC_BADGE_CLAIMS.has(row.claim_type))
    .map((row) => ({
      id: row.id,
      claimType: row.claim_type,
      label: proofBrokerClaimLabel(row.claim_type),
      outcome: row.outcome,
      issuedAt: row.issued_at,
    }))
}

function mapPost(row: Record<string, unknown>): AnonymousIdentityPost {
  return {
    id: row.id as string,
    identityId: row.identity_id as string,
    postUri: row.post_uri as string,
    communityUri: row.community_uri as string | null,
    postType: row.post_type as string,
    proofArtifactIds: JSON.parse((row.proof_artifact_ids_json as string) || '[]'),
    dmPolicy: row.dm_policy as AnonymousDmPolicy,
    stats: {
      replyCount: Number(row.reply_count ?? 0),
      repostCount: Number(row.repost_count ?? 0),
      likeCount: Number(row.like_count ?? 0),
      quoteCount: Number(row.quote_count ?? 0),
      threadCount: Number(row.thread_count ?? 0),
      syncedAt: row.stats_synced_at as string | null,
    },
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
  }
}

function mapGerm(row: Record<string, unknown>): AnonymousGermConnection {
  return {
    id: row.id as string,
    identityId: row.identity_id as string,
    provider: 'germ',
    providerRef: row.provider_ref as string,
    contactUrl: row.contact_url as string,
    mode: row.mode as AnonymousGermMode,
    status: row.status as 'active' | 'revoked',
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
    revokedAt: row.revoked_at as string | null,
  }
}

function getSessionIdentity(sessionId: string): { did: string } {
  const db = getDb()
  const row = db.prepare('SELECT did FROM sessions WHERE session_id = ?').get(sessionId) as { did: string } | undefined
  if (!row) throw appError('Session not found', 404, 'SESSION_NOT_FOUND')
  return row
}

function writeLedger(sessionId: string, action: string, targetType: string, targetId: string, detail: unknown) {
  const db = getDb()
  db.prepare(`
    INSERT INTO ledger (session_id, action, target_type, target_id, detail_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(sessionId, action, targetType, targetId, JSON.stringify(detail ?? {}), new Date().toISOString())
}

function normalizeStats(
  input: Partial<Omit<AnonymousPostStats, 'syncedAt'>> | undefined,
  existing?: AnonymousPostStats,
): AnonymousPostStats {
  return {
    replyCount: boundedCount(input?.replyCount ?? existing?.replyCount ?? 0),
    repostCount: boundedCount(input?.repostCount ?? existing?.repostCount ?? 0),
    likeCount: boundedCount(input?.likeCount ?? existing?.likeCount ?? 0),
    quoteCount: boundedCount(input?.quoteCount ?? existing?.quoteCount ?? 0),
    threadCount: boundedCount(input?.threadCount ?? existing?.threadCount ?? 0),
    syncedAt: new Date().toISOString(),
  }
}

function boundedCount(value: number) {
  if (!Number.isFinite(value)) return 0
  return Math.max(0, Math.trunc(value))
}

function appError(message: string, statusCode: number, code: string) {
  return Object.assign(new Error(message), { statusCode, code })
}
