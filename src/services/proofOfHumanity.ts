import { getDb } from '../db/connection.js'

/**
 * Proof-of-humanity for a session: an active INE proof artifact carrying a
 * ZK commitment (written by POST /v1/identity/ine/credential). Shared by the
 * civic-vote binding and claim verification.
 */
export function hasActiveIneCommitment(sessionId: string): boolean {
  const row = getDb()
    .prepare(`
      SELECT 1 AS found FROM proof_artifacts
      WHERE session_id = ?
        AND request_id = 'ine-verification'
        AND outcome = 'verified'
        AND status = 'active'
        AND commitment IS NOT NULL
      LIMIT 1
    `)
    .get(sessionId) as { found: number } | undefined
  return row !== undefined
}
