import { randomUUID } from 'node:crypto'
import { getDb } from '../db/connection.js'
import { appError } from '../utils/errors.js'

function writeLedger(sessionId: string, action: string, targetType: string, targetId: string, detail: unknown) {
  const db = getDb()
  db.prepare(`
    INSERT INTO ledger (session_id, action, target_type, target_id, detail_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(sessionId, action, targetType, targetId, JSON.stringify(detail ?? {}), new Date().toISOString())
}

/**
 * Follower graph for anonymous identities, tier-enforced by design:
 *
 * - Default anonymous profile ("main voice"): followable. Reputation
 *   (karma) already accrues here, so followers complete the contract.
 * - Isolated anonymous identities ("burner voices"): NOT followable. A
 *   follower graph is a correlation engine and would destroy their
 *   unlinkability, so the server rejects follow attempts outright.
 *
 * The graph is m8-side only; nothing is written to the public AT graph,
 * which would link the anonymous profile to the owner's public DID.
 */

type ResolvedTarget =
  | { kind: 'profile'; profileId: string }
  | { kind: 'isolated' }
  | { kind: 'missing' }

/**
 * Accepts either a default profile id (`anon-*`) or an identity id
 * (`anon-identity-*`). The folded default identity maps back to its profile;
 * any other identity is an isolated burner.
 */
function resolveFollowTarget(id: string): ResolvedTarget {
  const db = getDb()

  const profile = db
    .prepare('SELECT id FROM anonymous_profiles WHERE id = ?')
    .get(id) as { id: string } | undefined
  if (profile) return { kind: 'profile', profileId: profile.id }

  const identity = db
    .prepare('SELECT id FROM anonymous_identities WHERE id = ?')
    .get(id) as { id: string } | undefined
  if (!identity) return { kind: 'missing' }

  // The folded default identity is `anon-identity-<legacyProfileId>`.
  if (id.startsWith('anon-identity-')) {
    const legacyProfileId = id.slice('anon-identity-'.length)
    const folded = db
      .prepare('SELECT id FROM anonymous_profiles WHERE id = ?')
      .get(legacyProfileId) as { id: string } | undefined
    if (folded) return { kind: 'profile', profileId: folded.id }
  }

  return { kind: 'isolated' }
}

function requireProfileTarget(id: string): string {
  const target = resolveFollowTarget(id)
  if (target.kind === 'isolated') {
    throw appError(
      'Isolated identities cannot be followed: burner voices have no social graph by design',
      403,
      'ISOLATED_NOT_FOLLOWABLE',
    )
  }
  if (target.kind === 'missing') {
    throw appError('Anonymous profile not found', 404, 'ANON_PROFILE_NOT_FOUND')
  }
  return target.profileId
}

function followerCount(profileId: string): number {
  const row = getDb()
    .prepare('SELECT COUNT(*) AS count FROM anonymous_follows WHERE followed_profile_id = ?')
    .get(profileId) as { count: number }
  return row.count
}

function requireFollowerProfile(sessionId: string): string {
  const row = getDb()
    .prepare('SELECT id FROM anonymous_profiles WHERE session_id = ?')
    .get(sessionId) as { id: string } | undefined
  if (!row) {
    throw appError(
      'Enable your default anonymous identity before following voices',
      400,
      'ANON_PROFILE_REQUIRED',
    )
  }
  return row.id
}

function ownerSessionOf(profileId: string): string | null {
  const row = getDb()
    .prepare('SELECT session_id FROM anonymous_profiles WHERE id = ?')
    .get(profileId) as { session_id: string } | undefined
  return row?.session_id ?? null
}

export function followAnonymousProfile(sessionId: string, targetId: string) {
  const profileId = requireProfileTarget(targetId)
  const followerProfileId = requireFollowerProfile(sessionId)

  if (ownerSessionOf(profileId) === sessionId) {
    throw appError('You cannot follow your own voice', 400, 'CANNOT_FOLLOW_SELF')
  }

  const db = getDb()
  db.prepare(`
    INSERT OR IGNORE INTO anonymous_follows (id, follower_session_id, followed_profile_id, created_at)
    VALUES (?, ?, ?, ?)
  `).run(`anon-follow-${randomUUID()}`, sessionId, profileId, new Date().toISOString())

  writeLedger(sessionId, 'AnonymousProfileFollowed', 'anonymous_profile', profileId, {})
  return { following: true, followerCount: followerCount(profileId), profileId, followerProfileId }
}

export function unfollowAnonymousProfile(sessionId: string, targetId: string) {
  const profileId = requireProfileTarget(targetId)

  getDb()
    .prepare('DELETE FROM anonymous_follows WHERE follower_session_id = ? AND followed_profile_id = ?')
    .run(sessionId, profileId)

  return { following: false, followerCount: followerCount(profileId), profileId }
}

export function getAnonymousProfilePublic(sessionId: string, targetId: string) {
  const profileId = requireProfileTarget(targetId)
  const db = getDb()
  const profile = db
    .prepare('SELECT id, display_name, avatar_seed, created_at FROM anonymous_profiles WHERE id = ?')
    .get(profileId) as { id: string; display_name: string; avatar_seed: string; created_at: string }

  const followRow = db
    .prepare('SELECT 1 AS found FROM anonymous_follows WHERE follower_session_id = ? AND followed_profile_id = ?')
    .get(sessionId, profileId)

  return {
    profile: {
      id: profile.id,
      displayName: profile.display_name,
      avatarSeed: profile.avatar_seed,
      createdAt: profile.created_at,
    },
    followerCount: followerCount(profileId),
    following: followRow !== undefined,
  }
}
