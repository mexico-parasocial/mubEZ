import { randomBytes, timingSafeEqual } from 'node:crypto'
import { getDb } from '../db/connection.js'

/**
 * Per-session issuance challenge (replay protection for credential issuance,
 * per PARA_INTEGRATION_CONTRACT.md). The challenge is a random 256-bit nonce
 * stored on the session row, exposed via GET /v1/sessions/me, required in the
 * credential request payload, and rotated after every issuance attempt.
 */

export function ensureIssuanceChallenge(sessionId: string): string {
  const db = getDb()
  const row = db
    .prepare('SELECT issuance_challenge AS challenge FROM sessions WHERE session_id = ?')
    .get(sessionId) as { challenge: string | null } | undefined
  if (row?.challenge) return row.challenge

  const challenge = randomBytes(32).toString('base64url')
  db.prepare('UPDATE sessions SET issuance_challenge = ?, updated_at = ? WHERE session_id = ?')
    .run(challenge, new Date().toISOString(), sessionId)
  return challenge
}

export function rotateIssuanceChallenge(sessionId: string): string {
  const challenge = randomBytes(32).toString('base64url')
  getDb()
    .prepare('UPDATE sessions SET issuance_challenge = ?, updated_at = ? WHERE session_id = ?')
    .run(challenge, new Date().toISOString(), sessionId)
  return challenge
}

export function isValidIssuanceChallenge(sessionId: string, presented: string): boolean {
  const row = getDb()
    .prepare('SELECT issuance_challenge AS challenge FROM sessions WHERE session_id = ?')
    .get(sessionId) as { challenge: string | null } | undefined
  if (!row?.challenge || !presented) return false
  const expected = Buffer.from(row.challenge)
  const candidate = Buffer.from(presented)
  return expected.length === candidate.length && timingSafeEqual(expected, candidate)
}
