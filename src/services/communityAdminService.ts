import { getDb } from '../db/connection.js'
import type { CommunityAdmin } from '../types/index.js'
import { MIN_COMMUNITY_ADMINS } from '../types/index.js'
import { getCommunity, updateCommunityStatus } from './communityService.js'
import { appError } from '../utils/errors.js'
import { nowIso } from '../utils/time.js'
import { mapAdmin } from './community/mappers.js'

export function isAdmin(communityId: string, did: string): boolean {
  const db = getDb()
  const row = db
    .prepare(
      'SELECT 1 FROM community_admins WHERE community_id = ? AND admin_did = ? AND status = ?'
    )
    .get(communityId, did, 'active') as Record<string, unknown> | undefined
  return !!row
}

export function getAdminCount(communityId: string): number {
  const db = getDb()
  const row = db
    .prepare(
      "SELECT COUNT(*) as count FROM community_admins WHERE community_id = ? AND status = 'active'"
    )
    .get(communityId) as Record<string, unknown>
  return (row.count as number) ?? 0
}

export function listAdmins(communityId: string): CommunityAdmin[] {
  const db = getDb()
  const rows = db
    .prepare('SELECT * FROM community_admins WHERE community_id = ? ORDER BY added_at ASC')
    .all(communityId) as Record<string, unknown>[]
  return rows.map(mapAdmin)
}

export function addAdmin(
  communityId: string,
  adminDid: string,
  addedByDid: string
): CommunityAdmin {
  const db = getDb()
  const now = nowIso()

  // Verify community exists
  const community = getCommunity(communityId)
  if (!community) {
    throw appError('Community not found', 404, 'COMMUNITY_NOT_FOUND')
  }

  // Check if already an active admin
  const existing = db
    .prepare('SELECT status FROM community_admins WHERE community_id = ? AND admin_did = ?')
    .get(communityId, adminDid) as Record<string, unknown> | undefined

  if (existing?.status === 'active') {
    throw appError('This DID is already an admin of this community', 409, 'ADMIN_ALREADY_EXISTS')
  }

  if (existing?.status === 'removed') {
    // Reactivate
    db.prepare(
      'UPDATE community_admins SET status = ?, added_by_did = ?, added_at = ? WHERE community_id = ? AND admin_did = ?'
    ).run('active', addedByDid, now, communityId, adminDid)
  } else {
    db.prepare(
      'INSERT INTO community_admins (community_id, admin_did, added_by_did, added_at, status) VALUES (?, ?, ?, ?, ?)'
    ).run(communityId, adminDid, addedByDid, now, 'active')
  }

  // Check if we should activate the community
  const adminCount = getAdminCount(communityId)
  if (community.status === 'pending_admins' && adminCount >= MIN_COMMUNITY_ADMINS) {
    updateCommunityStatus(communityId, 'active')
  }

  const row = db
    .prepare('SELECT * FROM community_admins WHERE community_id = ? AND admin_did = ?')
    .get(communityId, adminDid) as Record<string, unknown>
  return mapAdmin(row)
}

export function removeAdmin(
  communityId: string,
  adminDid: string,
  _removedByDid: string
): void {
  const db = getDb()

  const community = getCommunity(communityId)
  if (!community) {
    throw appError('Community not found', 404, 'COMMUNITY_NOT_FOUND')
  }

  const adminCount = getAdminCount(communityId)
  if (adminCount <= MIN_COMMUNITY_ADMINS) {
    throw appError(
      `Cannot remove admin: community must maintain at least ${MIN_COMMUNITY_ADMINS} admins`,
      409,
      'MIN_ADMINS_REQUIRED'
    )
  }

  const result = db
    .prepare(
      "UPDATE community_admins SET status = 'removed' WHERE community_id = ? AND admin_did = ? AND status = 'active'"
    )
    .run(communityId, adminDid)

  if (result.changes === 0) {
    throw appError('Admin not found or already removed', 404, 'ADMIN_NOT_FOUND')
  }
}

export function assertIsAdmin(communityId: string, did: string): void {
  if (!isAdmin(communityId, did)) {
    throw appError('You must be an admin of this community to perform this action', 403, 'NOT_ADMIN')
  }
}

export function bootstrapCommunityAdmins(
  communityId: string,
  requestedByDid: string,
  adminDids: string[]
): { admins: CommunityAdmin[] } {
  const db = getDb()
  const community = getCommunity(communityId)
  if (!community) {
    throw appError('Community not found', 404, 'COMMUNITY_NOT_FOUND')
  }
  if (community.status !== 'pending_admins') {
    throw appError('Community bootstrap is only available before activation', 409, 'COMMUNITY_ALREADY_ACTIVE')
  }
  if (community.bootstrapUsedAt) {
    throw appError('Community admin bootstrap has already been used', 409, 'BOOTSTRAP_ALREADY_USED')
  }
  assertIsAdmin(communityId, requestedByDid)

  const uniqueAdminDids = [...new Set(adminDids.map((did) => did.trim()).filter(Boolean))]
  const activeAdmins = listAdmins(communityId).filter((admin) => admin.status === 'active')
  const activeDidSet = new Set(activeAdmins.map((admin) => admin.adminDid))
  const newAdminDids = uniqueAdminDids.filter((did) => !activeDidSet.has(did))

  if (activeAdmins.length + newAdminDids.length < MIN_COMMUNITY_ADMINS) {
    throw appError(
      `Bootstrap must establish at least ${MIN_COMMUNITY_ADMINS} active admins`,
      422,
      'MIN_ADMINS_REQUIRED'
    )
  }

  const now = nowIso()
  db.transaction(() => {
    for (const adminDid of newAdminDids) {
      const existing = db
        .prepare('SELECT status FROM community_admins WHERE community_id = ? AND admin_did = ?')
        .get(communityId, adminDid) as Record<string, unknown> | undefined

      if (existing) {
        db.prepare(
          'UPDATE community_admins SET status = ?, added_by_did = ?, added_at = ? WHERE community_id = ? AND admin_did = ?'
        ).run('active', requestedByDid, now, communityId, adminDid)
      } else {
        db.prepare(
          'INSERT INTO community_admins (community_id, admin_did, added_by_did, added_at, status) VALUES (?, ?, ?, ?, ?)'
        ).run(communityId, adminDid, requestedByDid, now, 'active')
      }
    }

    db.prepare(
      "UPDATE communities SET bootstrap_used_at = ?, status = 'active', updated_at = ? WHERE id = ?"
    ).run(now, now, communityId)
  })()

  return { admins: listAdmins(communityId).filter((admin) => admin.status === 'active') }
}
