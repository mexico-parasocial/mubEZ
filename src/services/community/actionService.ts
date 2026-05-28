import { randomUUID } from 'node:crypto'
import { getDb } from '../../db/connection.js'
import type { CommunityAction, CommunityActionType, CommunityActionStatus } from '../../types/index.js'
import { COMMUNITY_ACTION_THRESHOLDS } from '../../types/index.js'
import { getCommunity } from '../communityService.js'
import { assertIsAdmin, getAdminCount, isAdmin } from '../communityAdminService.js'
import { appError } from '../../utils/errors.js'
import { nowIso } from '../../utils/time.js'
import { mapAction, mapVote } from './mappers.js'

function getRequiredApprovals(actionType: CommunityActionType, adminCount: number): number {
  const threshold = COMMUNITY_ACTION_THRESHOLDS[actionType]
  if (!threshold) {
    throw appError(`Unknown action type: ${actionType}`, 400, 'UNKNOWN_ACTION_TYPE')
  }
  if (threshold.impact === 'high') {
    return Math.max(threshold.required, adminCount)
  }
  return threshold.required
}

export function proposeAction(
  communityId: string,
  proposedByDid: string,
  actionType: CommunityActionType,
  payload: Record<string, unknown>
): CommunityAction {
  const db = getDb()
  const now = nowIso()

  const community = getCommunity(communityId)
  if (!community) {
    throw appError('Community not found', 404, 'COMMUNITY_NOT_FOUND')
  }

  if (community.status !== 'active') {
    throw appError(
      `Community must be active to propose actions. Current status: ${community.status}`,
      409,
      'COMMUNITY_NOT_ACTIVE'
    )
  }

  assertIsAdmin(communityId, proposedByDid)

  const adminCount = getAdminCount(communityId)
  const requiredApprovals = getRequiredApprovals(actionType, adminCount)

  if (actionType === 'admin_add') {
    const newAdminDid = payload.adminDid as string
    if (!newAdminDid) {
      throw appError('adminDid is required for admin_add actions', 422, 'MISSING_ADMIN_DID')
    }
    if (isAdmin(communityId, newAdminDid)) {
      throw appError('This DID is already an admin', 409, 'ADMIN_ALREADY_EXISTS')
    }
  }

  if (actionType === 'admin_remove') {
    const removeAdminDid = payload.adminDid as string
    if (!removeAdminDid) {
      throw appError('adminDid is required for admin_remove actions', 422, 'MISSING_ADMIN_DID')
    }
    if (removeAdminDid === proposedByDid) {
      throw appError('You cannot remove yourself via action. Use leave instead.', 409, 'SELF_REMOVE_NOT_ALLOWED')
    }
    if (!isAdmin(communityId, removeAdminDid)) {
      throw appError('This DID is not an admin', 404, 'ADMIN_NOT_FOUND')
    }
    if (adminCount <= 3) {
      throw appError(
        'Cannot remove admin: community must maintain at least 3 admins',
        409,
        'MIN_ADMINS_REQUIRED'
      )
    }
  }

  const actionId = `action-${randomUUID()}`

  db.prepare(`
    INSERT INTO community_actions (id, community_id, action_type, impact_level, payload, proposed_by_did, status, required_approvals, current_approvals, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    actionId,
    communityId,
    actionType,
    COMMUNITY_ACTION_THRESHOLDS[actionType].impact,
    JSON.stringify(payload),
    proposedByDid,
    'pending',
    requiredApprovals,
    0,
    now
  )

  const row = db.prepare('SELECT * FROM community_actions WHERE id = ?').get(actionId) as Record<string, unknown>
  return mapAction(row)
}

export function getAction(actionId: string): CommunityAction & { votes: import('../../types/index.js').CommunityActionVoteRecord[] } {
  const db = getDb()
  const row = db.prepare('SELECT * FROM community_actions WHERE id = ?').get(actionId) as
    | Record<string, unknown>
    | undefined
  if (!row) {
    throw appError('Action not found', 404, 'ACTION_NOT_FOUND')
  }

  const voteRows = db
    .prepare('SELECT * FROM community_action_votes WHERE action_id = ? ORDER BY voted_at ASC')
    .all(actionId) as Record<string, unknown>[]

  return {
    ...mapAction(row),
    votes: voteRows.map((r) => mapVote(r)),
  }
}

export function listActions(
  communityId: string,
  opts?: { status?: CommunityActionStatus; limit?: number; offset?: number }
): {
  actions: CommunityAction[]
  total: number
} {
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
    .prepare(`SELECT * FROM community_actions ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`)
    .all(...params) as Record<string, unknown>[]

  const countParams: (string | number)[] = [communityId]
  if (opts?.status) countParams.push(opts.status)

  const countRow = db
    .prepare(`SELECT COUNT(*) as count FROM community_actions ${whereClause}`)
    .get(...countParams) as Record<string, unknown>

  return {
    actions: rows.map(mapAction),
    total: (countRow.count as number) ?? 0,
  }
}
