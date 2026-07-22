import { getDb } from '../db/connection.js'
import { hasActiveIneCommitment } from './proofOfHumanity.js'

/**
 * Server-derived karma. The client reports an action; the server decides how
 * many points it is worth and verifies that the action actually happened.
 * Client-sent point values are never trusted.
 */

type KarmaActionDef = {
  points: number
  /** Idempotency key derived from the action detail (null = missing subject). */
  subjectKey: (detail: Record<string, unknown>) => string | null
  /** Server-side proof that the action occurred for this session. */
  verify: (sessionId: string, detail: Record<string, unknown>) => boolean
}

export const KARMA_ACTIONS: Record<string, KarmaActionDef> = {
  civic_vote_cast: {
    points: 2,
    subjectKey: (d) =>
      typeof d.subjectUri === 'string' && d.subjectUri ? `vote:${d.subjectUri}` : null,
    verify: (sessionId, d) => {
      const row = getDb()
        .prepare(
          'SELECT 1 AS found FROM civic_vote_nullifiers WHERE session_id = ? AND subject_uri = ? LIMIT 1',
        )
        .get(sessionId, d.subjectUri)
      return row !== undefined
    },
  },
  ine_credential_issued: {
    points: 10,
    subjectKey: () => 'ine-credential',
    verify: (sessionId) => hasActiveIneCommitment(sessionId),
  },
  anonymous_post_linked: {
    points: 1,
    subjectKey: (d) =>
      typeof d.postUri === 'string' && d.postUri ? `post:${d.postUri}` : null,
    verify: (sessionId, d) => {
      const row = getDb()
        .prepare(
          `SELECT 1 AS found
           FROM anonymous_identity_posts p
           JOIN anonymous_identities i ON i.id = p.identity_id
           WHERE i.session_id = ? AND p.post_uri = ?
           LIMIT 1`,
        )
        .get(sessionId, d.postUri)
      return row !== undefined
    },
  },
}

export type KarmaEarnResult =
  | { ok: true; points: number; subjectKey: string }
  | { ok: false; status: number; code: string; error: string }

export function evaluateKarmaEarn(
  sessionId: string,
  actionType: string,
  detail: Record<string, unknown>,
): KarmaEarnResult {
  const def = KARMA_ACTIONS[actionType]
  if (!def) {
    return {
      ok: false,
      status: 400,
      code: 'UNKNOWN_KARMA_ACTION',
      error: `Unknown karma action: ${actionType}`,
    }
  }

  const subjectKey = def.subjectKey(detail)
  if (!subjectKey) {
    return {
      ok: false,
      status: 400,
      code: 'KARMA_SUBJECT_REQUIRED',
      error: `Action ${actionType} requires a subject in detail (e.g. subjectUri or postUri).`,
    }
  }

  if (!def.verify(sessionId, detail)) {
    return {
      ok: false,
      status: 403,
      code: 'KARMA_ACTION_NOT_VERIFIED',
      error: `Action ${actionType} could not be verified for this session.`,
    }
  }

  return { ok: true, points: def.points, subjectKey }
}
