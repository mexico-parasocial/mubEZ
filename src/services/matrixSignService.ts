import { randomUUID } from 'node:crypto'
import { getDb } from '../db/connection.js'
import {
  verifyIdentityAssertion,
  type SigPurpose,
  type SignedAssertion,
} from './identitySignature.js'

/*
 * Matrix sign-request relay (CD-M6 client adoption, W1a).
 *
 * PARA cannot sign CD-M4 assertions — the identity keys live in the iM8
 * wallet, and the broker deliberately never holds key material either. What
 * it can be is a session-bound mailbox: PARA (the app) drops a sign request
 * carrying the bridge's one-time challenge onto its own M8 session, the iM8
 * wallet lists pending requests for that session, the user approves, iM8
 * signs locally and posts the assertion back, and PARA polls it out.
 *
 * The relay verifies before storing: an assertion is only accepted for a
 * request whose (purpose, audience, challenge) it actually signs —
 * `verifyIdentityAssertion` — so the mailbox can never hand PARA a signature
 * for anything but exactly the challenge PARA deposited. Everything expires
 * with the bridge challenge TTL (5 minutes). The broker sees public keys and
 * signatures only; nothing here can sign.
 */

/** Matches the bridge's ChallengeStore TTL: the challenge dies with it. */
export const MATRIX_SIGN_REQUEST_TTL_SEC = 5 * 60
/** Cap on outstanding requests per session, to bound abuse. */
export const MAX_PENDING_SIGN_REQUESTS_PER_SESSION = 10

export const MATRIX_SIGN_PURPOSE: SigPurpose = 'matrix-login'

let schemaReady = false

function ensureSchema(): void {
  if (schemaReady) return
  getDb()
    .prepare(
      `CREATE TABLE IF NOT EXISTS matrix_sign_requests (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        challenge TEXT NOT NULL,
        audience TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        assertion_json TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        expires_at TEXT NOT NULL
      )`,
    )
    .run()
  schemaReady = true
}

function pruneExpired(): void {
  ensureSchema()
  getDb()
    .prepare(
      "DELETE FROM matrix_sign_requests WHERE expires_at <= datetime('now')",
    )
    .run()
}

export interface MatrixSignRequestRow {
  id: string
  challenge: string
  audience: string
  status: 'pending' | 'fulfilled'
  createdAt: string
  expiresAt: string
}

const rowToView = (row: Record<string, unknown>): MatrixSignRequestRow => ({
  id: row.id as string,
  challenge: row.challenge as string,
  audience: row.audience as string,
  status: row.status as 'pending' | 'fulfilled',
  createdAt: row.created_at as string,
  expiresAt: row.expires_at as string,
})

export function createMatrixSignRequest(
  sessionId: string,
  input: { challenge: string; audience: string },
): MatrixSignRequestRow {
  ensureSchema()
  pruneExpired()

  const pending = getDb()
    .prepare(
      "SELECT COUNT(*) as count FROM matrix_sign_requests WHERE session_id = ? AND status = 'pending'",
    )
    .get(sessionId) as { count: number }
  if (pending.count >= MAX_PENDING_SIGN_REQUESTS_PER_SESSION) {
    throw new Error('Too many pending sign requests for this session')
  }

  const id = randomUUID()
  getDb()
    .prepare(
      `INSERT INTO matrix_sign_requests (id, session_id, challenge, audience, expires_at)
       VALUES (?, ?, ?, ?, datetime('now', '+${MATRIX_SIGN_REQUEST_TTL_SEC} seconds'))`,
    )
    .run(id, sessionId, input.challenge, input.audience)
  const row = getDb()
    .prepare('SELECT * FROM matrix_sign_requests WHERE id = ?')
    .get(id) as Record<string, unknown>
  return rowToView(row)
}

export function listPendingMatrixSignRequests(
  sessionId: string,
): MatrixSignRequestRow[] {
  ensureSchema()
  pruneExpired()
  const rows = getDb()
    .prepare(
      "SELECT * FROM matrix_sign_requests WHERE session_id = ? AND status = 'pending' ORDER BY created_at DESC",
    )
    .all(sessionId) as Array<Record<string, unknown>>
  return rows.map(rowToView)
}

export function getMatrixSignRequest(
  sessionId: string,
  id: string,
):
  | (MatrixSignRequestRow & { assertion?: SignedAssertion })
  | undefined {
  ensureSchema()
  pruneExpired()
  const row = getDb()
    .prepare('SELECT * FROM matrix_sign_requests WHERE id = ? AND session_id = ?')
    .get(id, sessionId) as Record<string, unknown> | undefined
  if (!row) return undefined
  const view = rowToView(row)
  if (row.assertion_json) {
    return { ...view, assertion: JSON.parse(row.assertion_json as string) }
  }
  return view
}

export type FulfillResult =
  | { ok: true }
  | { ok: false; reason: 'not-found' | 'not-pending' | 'invalid-proof' }

/**
 * The wallet posts the signed assertion. Accepted only if it verifies
 * against exactly this request's purpose, audience and challenge.
 */
export function fulfillMatrixSignRequest(
  sessionId: string,
  id: string,
  signed: SignedAssertion,
): FulfillResult {
  ensureSchema()
  pruneExpired()
  const row = getDb()
    .prepare('SELECT * FROM matrix_sign_requests WHERE id = ? AND session_id = ?')
    .get(id, sessionId) as Record<string, unknown> | undefined
  if (!row) return { ok: false, reason: 'not-found' }
  if (row.status !== 'pending') return { ok: false, reason: 'not-pending' }

  const valid = verifyIdentityAssertion(signed, {
    purpose: MATRIX_SIGN_PURPOSE,
    audience: row.audience as string,
    challenge: row.challenge as string,
  })
  if (!valid) return { ok: false, reason: 'invalid-proof' }

  getDb()
    .prepare(
      "UPDATE matrix_sign_requests SET status = 'fulfilled', assertion_json = ? WHERE id = ?",
    )
    .run(JSON.stringify(signed), id)
  return { ok: true }
}
