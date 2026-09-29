import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto'
import env from '#start/env'
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
  voteNullifier: string
  eligibilityProofRef: string
  issuedAt: string
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
    selectedOption?: number
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

  if (subjectType === 'cabildeo') {
    if (!Number.isSafeInteger(input.selectedOption) || input.selectedOption! < 0) {
      throw appError('selectedOption is required for a cabildeo proof', 400, 'INVALID_OPTION')
    }
    proofSecret()
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

  // 1-person-1-vote is only meaningful when the person root is the human, not
  // the session. Resolving it goes through the session's own INE artifact and
  // the `person_key` derived from that credential, so every session of the same
  // human lands on the same root and cannot mint a second vote.
  const person = resolvePersonRoot(sessionId)
  if (person.status !== 'active') {
    throw appError('Person identity is not active', 403, 'PERSON_NOT_ACTIVE')
  }

  // CD-12: no DID is recorded against the person root here. The nullifier is
  // derived from `person.id` alone, so an alias gate would authorise nothing
  // while linking the vote to the account it was cast from.
  const now = new Date().toISOString()
  const voteNullifier = computeVoteNullifier(person.id, subjectType, subjectUri)
  const existing = getExistingNullifier(person.id, subjectType, subjectUri)
  const proofRef = existing?.proof_ref ?? `m8:civic-vote-proof:${randomUUID()}`

  if (existing) {
    getDb()
      .prepare('UPDATE civic_vote_nullifiers SET last_used_at = ? WHERE id = ?')
      .run(now, existing.id)
  } else {
    getDb()
      .prepare(`
        INSERT INTO civic_vote_nullifiers
          (id, person_id, subject_uri, subject_type, vote_nullifier, proof_ref, issued_at, last_used_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        `civic-nullifier-${randomUUID()}`,
        person.id,
        subjectUri,
        subjectType,
        voteNullifier,
        proofRef,
        now,
        now,
      )
  }

  // Never log the session together with a nullifier, subject or proof reference.
  const eligibilityProofRef = subjectType === 'cabildeo'
    ? cabildeoProofMac({
        actorDid: getSessionIdentity(sessionId).did,
        subjectUri,
        selectedOption: input.selectedOption!,
        voteNullifier,
      }, proofRef)
    : proofRef

  return {
    subjectUri,
    subjectType,
    voteNullifier,
    eligibilityProofRef,
    issuedAt: existing?.issued_at ?? now,
  }
}

export interface CabildeoProofClaim {
  actorDid: string
  subjectUri: string
  selectedOption: number
  voteNullifier: string
}

/** Verifies a public cabildeo authorization; does not expose person/session IDs. */
export function verifyCabildeoVoteProof(
  input: CabildeoProofClaim & { eligibilityProofRef: string },
): boolean {
  proofSecret()
  const row = getDb().prepare(`
    SELECT n.proof_ref FROM civic_vote_nullifiers n
    JOIN person_roots p ON p.id = n.person_id
    WHERE n.vote_nullifier = ? AND n.subject_type = 'cabildeo'
      AND n.subject_uri = ? AND p.status = 'active'
  `).get(input.voteNullifier, input.subjectUri) as { proof_ref: string } | undefined
  if (!row) return false
  const expected = Buffer.from(cabildeoProofMac(input, row.proof_ref))
  const supplied = Buffer.from(input.eligibilityProofRef)
  return expected.length === supplied.length && timingSafeEqual(expected, supplied)
}

function proofSecret(): string {
  const secret = env.get('CIVIC_VOTE_PROOF_SECRET')
  if (!secret) throw appError('Civic vote verification is unavailable', 503, 'VOTE_VERIFIER_UNAVAILABLE')
  return secret
}

function cabildeoProofMac(input: CabildeoProofClaim, proofRef: string): string {
  const mac = createHmac('sha256', proofSecret())
    .update(JSON.stringify([
      'm8:public-cabildeo-authorization:v1', proofRef, input.voteNullifier,
      input.subjectUri, input.actorDid, input.selectedOption,
    ]))
    .digest('base64url')
  return `m8:cabildeo:v1:${mac}`
}

/**
 * The person behind a session, filed under the credential rather than the
 * session.
 *
 * The `person_key` is written onto the INE proof artifact when the credential
 * is issued (`ine_controller`), derived from the peppered `curp_hash`. A second
 * enrolment by the same human therefore resolves to the row already there,
 * which is what makes one person one vote hold across sessions and devices.
 */
export function resolvePersonRoot(sessionId: string): PersonRoot {
  const db = getDb()
  const artifact = db
    .prepare(`
      SELECT person_key FROM proof_artifacts
      WHERE session_id = ?
        AND request_id = 'ine-verification'
        AND outcome = 'verified'
        AND status = 'active'
        AND person_key IS NOT NULL
      ORDER BY issued_at DESC
      LIMIT 1
    `)
    .get(sessionId) as { person_key: string } | undefined

  if (!artifact) {
    throw appError(
      'Identity verification (INE) is required before voting: no active identity commitment for this session',
      403,
      'INE_COMMITMENT_REQUIRED',
    )
  }

  const existing = db
    .prepare('SELECT id, status FROM person_roots WHERE person_key = ?')
    .get(artifact.person_key) as PersonRoot | undefined
  if (existing) return existing

  const now = new Date().toISOString()
  const id = `person-${randomUUID()}`
  db.prepare(`
    INSERT INTO person_roots (id, person_key, status, created_at, updated_at)
    VALUES (?, ?, 'active', ?, ?)
  `).run(id, artifact.person_key, now, now)
  return { id, status: 'active' }
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


export function getSessionIdentity(sessionId: string): SessionIdentity {
  const row = getDb()
    .prepare('SELECT did, handle FROM sessions WHERE session_id = ? AND status = ?')
    .get(sessionId, 'active') as SessionIdentity | undefined
  if (!row) throw appError('Session not found', 404, 'SESSION_NOT_FOUND')
  return row
}

export function computeVoteNullifier(personId: string, subjectType: string, subjectUri: string) {
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
