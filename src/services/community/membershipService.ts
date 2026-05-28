import { getDb } from '../../db/connection.js'
import type { CommunityMembership, CommunityMembershipStatus } from '../../types/index.js'
import { appError } from '../../utils/errors.js'
import { nowIso } from '../../utils/time.js'
import { mapMembership } from './mappers.js'

export function listMemberships(
  communityId: string,
  opts?: { status?: CommunityMembershipStatus; limit?: number; offset?: number }
): { memberships: CommunityMembership[]; total: number } {
  const db = getDb()
  const limit = opts?.limit ?? 50
  const offset = opts?.offset ?? 0

  let whereClause = 'WHERE community_id = ?'
  const params: (string | number)[] = [communityId]

  if (opts?.status) {
    whereClause += ' AND status = ?'
    params.push(opts.status)
  }
  params.push(limit, offset)

  const rows = db
    .prepare(`SELECT * FROM community_memberships ${whereClause} ORDER BY joined_at DESC LIMIT ? OFFSET ?`)
    .all(...params) as Record<string, unknown>[]

  const countParams: (string | number)[] = [communityId]
  if (opts?.status) countParams.push(opts.status)

  const countRow = db
    .prepare(`SELECT COUNT(*) as count FROM community_memberships ${whereClause}`)
    .get(...countParams) as Record<string, unknown>

  return {
    memberships: rows.map(mapMembership),
    total: (countRow.count as number) ?? 0,
  }
}

export function getMembership(communityId: string, memberDid: string): CommunityMembership | undefined {
  const db = getDb()
  const row = db
    .prepare('SELECT * FROM community_memberships WHERE community_id = ? AND member_did = ?')
    .get(communityId, memberDid) as Record<string, unknown> | undefined

  return row ? mapMembership(row) : undefined
}

export function requestMembership(communityId: string, memberDid: string): CommunityMembership {
  const db = getDb()
  const now = nowIso()

  const existing = db
    .prepare('SELECT status FROM community_memberships WHERE community_id = ? AND member_did = ?')
    .get(communityId, memberDid) as Record<string, unknown> | undefined

  if (existing?.status === 'active' || existing?.status === 'pending') {
    throw appError('Membership request already exists', 409, 'MEMBERSHIP_EXISTS')
  }

  if (existing?.status === 'left') {
    db.prepare(
      'UPDATE community_memberships SET status = ?, joined_at = ?, left_at = NULL WHERE community_id = ? AND member_did = ?'
    ).run('pending', now, communityId, memberDid)
  } else {
    db.prepare(
      'INSERT INTO community_memberships (community_id, member_did, status, joined_at) VALUES (?, ?, ?, ?)'
    ).run(communityId, memberDid, 'pending', now)
  }

  return getMembership(communityId, memberDid)!
}

export function approveMembership(communityId: string, memberDid: string): boolean {
  const db = getDb()
  const now = nowIso()

  const result = db
    .prepare(
      "UPDATE community_memberships SET status = 'active', joined_at = ? WHERE community_id = ? AND member_did = ? AND status = 'pending'"
    )
    .run(now, communityId, memberDid)

  return result.changes > 0
}

export function rejectMembership(communityId: string, memberDid: string): boolean {
  const db = getDb()

  const result = db
    .prepare(
      "DELETE FROM community_memberships WHERE community_id = ? AND member_did = ? AND status = 'pending'"
    )
    .run(communityId, memberDid)

  return result.changes > 0
}

export function leaveMembership(communityId: string, memberDid: string): boolean {
  const db = getDb()
  const now = nowIso()

  const result = db
    .prepare(
      "UPDATE community_memberships SET status = 'left', left_at = ? WHERE community_id = ? AND member_did = ? AND status = 'active'"
    )
    .run(now, communityId, memberDid)

  return result.changes > 0
}

export function updateMembershipUris(
  communityId: string,
  memberDid: string,
  uris: { groupRecordUri?: string | null; membershipRecordUri?: string | null }
): void {
  const db = getDb()
  db.prepare(
    'UPDATE community_memberships SET group_record_uri = ?, membership_record_uri = ? WHERE community_id = ? AND member_did = ?'
  ).run(uris.groupRecordUri ?? null, uris.membershipRecordUri ?? null, communityId, memberDid)
}
