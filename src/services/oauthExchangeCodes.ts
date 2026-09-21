import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { getDb } from '../db/connection.js'

const EXCHANGE_CODE_TTL_MS = 2 * 60 * 1000

export type ExchangeCodeErrorKind = 'invalid' | 'expired' | 'reused'

export class ExchangeCodeError extends Error {
  constructor(readonly kind: ExchangeCodeErrorKind) {
    super(`OAuth exchange code ${kind}`)
  }
}

export type ConsumedExchangeCode = {
  sessionId: string
  attemptId: string
}

function hashCode(code: string): string {
  return createHash('sha256').update(code).digest('hex')
}

function nowIso() {
  return new Date().toISOString()
}

/**
 * Mints a one-time exchange code bound to a completed OAuth attempt's session.
 * Only the SHA-256 hash is stored — the plaintext code exists solely in the
 * deep-link redirect URL handed to the native app.
 */
export function createExchangeCode(input: {
  attemptId: string
  sessionId: string
}): { code: string; expiresAt: string } {
  const code = `m8ex-${randomBytes(32).toString('base64url')}`
  const createdAt = nowIso()
  const expiresAt = new Date(Date.now() + EXCHANGE_CODE_TTL_MS).toISOString()

  getDb()
    .prepare(`
      INSERT INTO oauth_exchange_codes
        (id, code_hash, attempt_id, session_id, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `)
    .run(`oauth-exchange-${randomUUID()}`, hashCode(code), input.attemptId, input.sessionId, createdAt, expiresAt)

  return { code, expiresAt }
}

/**
 * Single-use consumption: the `used_at IS NULL` guard inside the UPDATE makes
 * a replayed code lose the race deterministically, mirroring the token
 * rotation guarantee in tokenService.
 */
export function consumeExchangeCode(code: string): ConsumedExchangeCode {
  const db = getDb()
  const now = nowIso()

  db.prepare('DELETE FROM oauth_exchange_codes WHERE expires_at < ?').run(now)

  const row = db
    .prepare('SELECT * FROM oauth_exchange_codes WHERE code_hash = ?')
    .get(hashCode(code)) as
    | { id: string; attempt_id: string; session_id: string; expires_at: string; used_at: string | null }
    | undefined

  if (!row) {
    // Unknown, already-consumed (row pruned later), or forged codes are
    // indistinguishable by design.
    throw new ExchangeCodeError('invalid')
  }
  if (row.expires_at < now) {
    throw new ExchangeCodeError('expired')
  }

  const consumed = db
    .prepare('UPDATE oauth_exchange_codes SET used_at = ? WHERE id = ? AND used_at IS NULL')
    .run(now, row.id)

  if (consumed.changes !== 1) {
    throw new ExchangeCodeError('reused')
  }

  return { sessionId: row.session_id, attemptId: row.attempt_id }
}
