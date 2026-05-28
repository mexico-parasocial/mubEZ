import { randomUUID } from 'node:crypto'
import { getDb } from '../db/connection.js'
import type { Community, CommunityStatus, CreateCommunityInput } from '../types/index.js'
import { provisionCommunityKeys } from './community/didService.js'
import { appError } from '../utils/errors.js'
import { nowIso } from '../utils/time.js'
import { mapCommunity } from './community/mappers.js'

export function createCommunity(
  sessionId: string,
  input: CreateCommunityInput
): Community {
  const db = getDb()
  const now = nowIso()

  // Get the founder's DID from their session
  const sessionRow = db.prepare('SELECT did FROM sessions WHERE session_id = ?').get(sessionId) as
    | Record<string, unknown>
    | undefined
  if (!sessionRow) {
    throw appError('Session not found', 404, 'SESSION_NOT_FOUND')
  }
  const founderDid = sessionRow.did as string

  // Validate DID uniqueness
  const existing = db.prepare('SELECT id FROM communities WHERE did = ?').get(input.did) as
    | Record<string, unknown>
    | undefined
  if (existing) {
    throw appError('Community with this DID already exists', 409, 'COMMUNITY_DID_EXISTS')
  }

  const communityId = `community-${randomUUID()}`

  db.prepare(`
    INSERT INTO communities (id, did, handle, name, description, pds_host, status, created_by_did, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    communityId,
    input.did,
    input.handle ?? null,
    input.name,
    input.description ?? '',
    input.pdsHost ?? '',
    'pending_admins',
    founderDid,
    now,
    now
  )

  // Founder becomes the first admin automatically
  db.prepare(`
    INSERT INTO community_admins (community_id, admin_did, added_by_did, added_at, status)
    VALUES (?, ?, ?, ?, ?)
  `).run(communityId, founderDid, founderDid, now, 'active')

  // Generate signing keys for the community
  provisionCommunityKeys(communityId)

  const row = db.prepare('SELECT * FROM communities WHERE id = ?').get(communityId) as Record<string, unknown>
  return mapCommunity(row)
}

export function getCommunity(communityId: string): Community | null {
  const db = getDb()
  const row = db.prepare('SELECT * FROM communities WHERE id = ?').get(communityId) as
    | Record<string, unknown>
    | undefined
  return row ? mapCommunity(row) : null
}

export function getCommunityByDid(did: string): Community | null {
  const db = getDb()
  const row = db.prepare('SELECT * FROM communities WHERE did = ?').get(did) as
    | Record<string, unknown>
    | undefined
  return row ? mapCommunity(row) : null
}

export function listCommunities(opts?: { status?: CommunityStatus; limit?: number; offset?: number }): {
  communities: Community[]
  total: number
} {
  const db = getDb()
  const limit = opts?.limit ?? 50
  const offset = opts?.offset ?? 0

  let whereClause = ''
  const params: (string | number)[] = [limit, offset]

  if (opts?.status) {
    whereClause = 'WHERE status = ?'
    params.unshift(opts.status)
  }

  const rows = db
    .prepare(`SELECT * FROM communities ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`)
    .all(...params) as Record<string, unknown>[]

  const countRow = db.prepare(`SELECT COUNT(*) as count FROM communities ${whereClause}`).get(
    ...(opts?.status ? [opts.status] : [])
  ) as Record<string, unknown>

  return {
    communities: rows.map(mapCommunity),
    total: (countRow.count as number) ?? 0,
  }
}

export function updateCommunityStatus(
  communityId: string,
  status: CommunityStatus
): Community {
  const db = getDb()
  const now = nowIso()

  const result = db
    .prepare('UPDATE communities SET status = ?, updated_at = ? WHERE id = ?')
    .run(status, now, communityId)

  if (result.changes === 0) {
    throw appError('Community not found', 404, 'COMMUNITY_NOT_FOUND')
  }

  const row = db.prepare('SELECT * FROM communities WHERE id = ?').get(communityId) as Record<string, unknown>
  return mapCommunity(row)
}

export function updateCommunityFromPayload(
  communityId: string,
  payload: Record<string, unknown>
): Community {
  const db = getDb()
  const now = nowIso()

  const setClauses: string[] = []
  const values: (string | number | null)[] = []

  if ('name' in payload) {
    setClauses.push('name = ?')
    values.push(payload.name as string)
  }
  if ('description' in payload) {
    setClauses.push('description = ?')
    values.push(payload.description as string)
  }
  if ('manifestoCid' in payload) {
    setClauses.push('manifesto_cid = ?')
    values.push((payload.manifestoCid as string) ?? null)
  }
  if ('politicalCompassX' in payload) {
    setClauses.push('political_compass_x = ?')
    values.push((payload.politicalCompassX as number) ?? null)
  }
  if ('politicalCompassY' in payload) {
    setClauses.push('political_compass_y = ?')
    values.push((payload.politicalCompassY as number) ?? null)
  }
  if ('rulesetCid' in payload) {
    setClauses.push('ruleset_cid = ?')
    values.push((payload.rulesetCid as string) ?? null)
  }

  if (setClauses.length === 0) {
    throw appError('No fields to update', 422, 'NO_UPDATE_FIELDS')
  }

  setClauses.push('updated_at = ?')
  values.push(now)
  values.push(communityId)

  const result = db
    .prepare(`UPDATE communities SET ${setClauses.join(', ')} WHERE id = ?`)
    .run(...values)

  if (result.changes === 0) {
    throw appError('Community not found', 404, 'COMMUNITY_NOT_FOUND')
  }

  const row = db.prepare('SELECT * FROM communities WHERE id = ?').get(communityId) as Record<string, unknown>
  return mapCommunity(row)
}
