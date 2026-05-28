import { createHash, randomUUID } from 'node:crypto'
import { getDb } from '../db/connection.js'
import { getCommunityByDid } from './communityService.js'

export type CivicVoteSubjectType =
  | 'cabildeo'
  | 'policy'
  | 'matter'
  | 'governance'
  | 'raq_axis'
  | 'raq_proposal'
  | 'community_proposal'
  | 'community_deliberation'
  | 'open_question_reply'

export interface CivicVoteProof {
  subjectUri: string
  subjectType: CivicVoteSubjectType
  aliasDid: string
  voteNullifier: string
  eligibilityProofRef: string
  issuedAt: string
  aliasDids: string[]
}

type SessionIdentity = {
  did: string
  handle: string
}

type PersonRoot = {
  id: string
  status: string
}

const VALID_SUBJECT_TYPES = new Set<CivicVoteSubjectType>([
  'cabildeo',
  'policy',
  'matter',
  'governance',
  'community_proposal',
  'community_deliberation',
  'open_question_reply',
  'raq_axis',
  'raq_proposal',
])

export function issueCivicVoteProof(
  sessionId: string,
  input: {
    subjectUri: string
    subjectType: CivicVoteSubjectType
    aliasDid?: string
  },
): CivicVoteProof {
  const subjectUri = input.subjectUri.trim()
  const subjectType = input.subjectType
  if (!subjectUri) {
    throw appError('subjectUri is required', 400, 'SUBJECT_URI_REQUIRED')
  }
  if (!VALID_SUBJECT_TYPES.has(subjectType)) {
    throw appError('Unsupported civic vote subject type', 400, 'INVALID_SUBJECT_TYPE')
  }

  // For community votes, validate membership
  if (subjectType === 'community_proposal' || subjectType === 'community_deliberation') {
    const communityDid = extractDidFromAtUri(subjectUri)
    if (communityDid) {
      const community = getCommunityByDid(communityDid)
      if (community) {
        const session = getSessionIdentity(sessionId)
        const isMember = getDb()
          .prepare('SELECT 1 FROM community_memberships WHERE community_id = ? AND member_did = ? AND status = ?')
          .get(community.id, session.did, 'active') as { '1': number } | undefined
        if (!isMember) {
          throw appError('You must be an active member of this community to vote', 403, 'NOT_COMMUNITY_MEMBER')
        }
      }
    }
  }

  const session = getSessionIdentity(sessionId)
  const person = ensurePersonRoot(sessionId)
  if (person.status !== 'active') {
    throw appError('Person identity is not active', 403, 'PERSON_NOT_ACTIVE')
  }

  ensureSessionAlias(person.id, sessionId, session)
  const aliasDid = input.aliasDid?.trim() || session.did
  const alias = getActiveAlias(person.id, aliasDid)
  if (!alias) {
    throw appError('Alias is not active for this person', 403, 'ALIAS_NOT_ACTIVE')
  }

  const now = new Date().toISOString()
  const voteNullifier = computeVoteNullifier(person.id, subjectType, subjectUri)
  const existing = getExistingNullifier(person.id, subjectType, subjectUri)
  const proofRef = existing?.proof_ref ?? `m8:civic-vote-proof:${randomUUID()}`

  if (existing) {
    getDb()
      .prepare(
        'UPDATE civic_vote_nullifiers SET session_id = ?, alias_did = ?, last_used_at = ? WHERE id = ?',
      )
      .run(sessionId, aliasDid, now, existing.id)
  } else {
    getDb()
      .prepare(`
        INSERT INTO civic_vote_nullifiers
          (id, person_id, session_id, alias_did, subject_uri, subject_type, vote_nullifier, proof_ref, issued_at, last_used_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        `civic-nullifier-${randomUUID()}`,
        person.id,
        sessionId,
        aliasDid,
        subjectUri,
        subjectType,
        voteNullifier,
        proofRef,
        now,
        now,
      )
  }

  writeLedger(sessionId, 'CivicVoteProofIssued', 'civic_vote_nullifier', voteNullifier, {
    subjectUri,
    subjectType,
    aliasDid,
    proofRef,
  })

  return {
    subjectUri,
    subjectType,
    aliasDid,
    voteNullifier,
    eligibilityProofRef: proofRef,
    issuedAt: existing?.issued_at ?? now,
    aliasDids: listActiveAliasDids(person.id),
  }
}

export function linkCivicVoteAlias(
  sessionId: string,
  input: {
    did: string
    handle?: string
  },
) {
  const did = input.did.trim()
  if (!did) throw appError('did is required', 400, 'DID_REQUIRED')
  const person = ensurePersonRoot(sessionId)
  const now = new Date().toISOString()
  const id = `person-alias-${randomUUID()}`
  getDb()
    .prepare(`
      INSERT INTO person_aliases (id, person_id, session_id, did, handle, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
      ON CONFLICT(person_id, did) DO UPDATE SET
        session_id = excluded.session_id,
        handle = excluded.handle,
        status = 'active',
        revoked_at = NULL,
        updated_at = excluded.updated_at
    `)
    .run(id, person.id, sessionId, did, input.handle?.trim() ?? '', now, now)

  writeLedger(sessionId, 'CivicVoteAliasLinked', 'person_alias', did, { did })
  return { did, status: 'active' as const, aliasDids: listActiveAliasDids(person.id) }
}

function ensurePersonRoot(sessionId: string): PersonRoot {
  const db = getDb()
  const existing = db
    .prepare('SELECT id, status FROM person_roots WHERE session_id = ?')
    .get(sessionId) as PersonRoot | undefined
  if (existing) return existing

  const now = new Date().toISOString()
  const id = `person-${randomUUID()}`
  db.prepare(`
    INSERT INTO person_roots (id, session_id, status, created_at, updated_at)
    VALUES (?, ?, 'active', ?, ?)
  `).run(id, sessionId, now, now)
  return { id, status: 'active' }
}

function ensureSessionAlias(personId: string, sessionId: string, session: SessionIdentity) {
  const now = new Date().toISOString()
  getDb()
    .prepare(`
      INSERT INTO person_aliases (id, person_id, session_id, did, handle, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
      ON CONFLICT(person_id, did) DO UPDATE SET
        session_id = excluded.session_id,
        handle = excluded.handle,
        status = 'active',
        revoked_at = NULL,
        updated_at = excluded.updated_at
    `)
    .run(`person-alias-${randomUUID()}`, personId, sessionId, session.did, session.handle, now, now)
}

function getActiveAlias(personId: string, did: string) {
  return getDb()
    .prepare('SELECT id FROM person_aliases WHERE person_id = ? AND did = ? AND status = ?')
    .get(personId, did, 'active') as { id: string } | undefined
}

function getExistingNullifier(personId: string, subjectType: string, subjectUri: string) {
  return getDb()
    .prepare(`
      SELECT id, proof_ref, issued_at
      FROM civic_vote_nullifiers
      WHERE person_id = ? AND subject_type = ? AND subject_uri = ?
    `)
    .get(personId, subjectType, subjectUri) as { id: string; proof_ref: string; issued_at: string } | undefined
}

function listActiveAliasDids(personId: string): string[] {
  const rows = getDb()
    .prepare('SELECT did FROM person_aliases WHERE person_id = ? AND status = ? ORDER BY created_at ASC')
    .all(personId, 'active') as Array<{ did: string }>
  return rows.map((row) => row.did)
}

function getSessionIdentity(sessionId: string): SessionIdentity {
  const row = getDb()
    .prepare('SELECT did, handle FROM sessions WHERE session_id = ? AND status = ?')
    .get(sessionId, 'active') as SessionIdentity | undefined
  if (!row) throw appError('Session not found', 404, 'SESSION_NOT_FOUND')
  return row
}

function computeVoteNullifier(personId: string, subjectType: string, subjectUri: string) {
  return createHash('sha256')
    .update('m8:civic-vote-nullifier:v1')
    .update('\0')
    .update(personId)
    .update('\0')
    .update(subjectType)
    .update('\0')
    .update(subjectUri)
    .digest('hex')
}

function writeLedger(sessionId: string, action: string, targetType: string, targetId: string, detail: unknown) {
  getDb()
    .prepare(`
      INSERT INTO ledger (session_id, action, target_type, target_id, detail_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `)
    .run(sessionId, action, targetType, targetId, JSON.stringify(detail ?? {}), new Date().toISOString())
}

function extractDidFromAtUri(uri: string): string | null {
  // AT URI format: at://did/collection/rkey
  if (!uri.startsWith('at://')) return null
  const rest = uri.slice(5) // remove 'at://'
  const slashIndex = rest.indexOf('/')
  if (slashIndex === -1) return rest
  return rest.slice(0, slashIndex)
}

function appError(message: string, statusCode: number, code: string) {
  return Object.assign(new Error(message), { statusCode, code })
}
