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
export function createExchangeCode(input: { attemptId: string; sessionId: string }): {
  code: string
  expiresAt: string
} {
  const code = `m8ex-${randomBytes(32).toString('base64url')}`
  const createdAt = nowIso()
  const expiresAt = new Date(Date.now() + EXCHANGE_CODE_TTL_MS).toISOString()
  const attempt = getDb()
    .prepare('SELECT exchange_challenge FROM oauth_login_attempts WHERE id = ?')
    .get(input.attemptId) as { exchange_challenge: string | null } | undefined

  getDb()
    .prepare(
      `
      INSERT INTO oauth_exchange_codes
        (id, code_hash, attempt_id, session_id, exchange_challenge, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
    )
    .run(
      `oauth-exchange-${randomUUID()}`,
      hashCode(code),
      input.attemptId,
      input.sessionId,
      attempt?.exchange_challenge ?? null,
      createdAt,
      expiresAt,
    )

  return { code, expiresAt }
}

/**
 * Single-use consumption: the `used_at IS NULL` guard inside the UPDATE makes
 * a replayed code lose the race deterministically, mirroring the token
 * rotation guarantee in tokenService.
 */
export function consumeExchangeCode(code: string, expectedAttemptId?: string, verifier?: string): ConsumedExchangeCode {
  const db = getDb()
  const now = nowIso()

  db.prepare('DELETE FROM oauth_exchange_codes WHERE expires_at < ?').run(now)

  const row = db.prepare('SELECT * FROM oauth_exchange_codes WHERE code_hash = ?').get(hashCode(code)) as
    | {
        id: string
        attempt_id: string
        session_id: string
        expires_at: string
        used_at: string | null
        exchange_challenge: string | null
      }
    | undefined

  if (!row || (expectedAttemptId && row.attempt_id !== expectedAttemptId)) {
    // Unknown, already-consumed (row pruned later), or forged codes are
    // indistinguishable by design.
    throw new ExchangeCodeError('invalid')
  }
  if (row.expires_at < now) {
    throw new ExchangeCodeError('expired')
  }
  if (
    row.exchange_challenge &&
    (!verifier ||
      !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) ||
      createHash('sha256').update(verifier).digest('base64url') !== row.exchange_challenge)
  )
    throw new ExchangeCodeError('invalid')

  const consumed = db
    .prepare('UPDATE oauth_exchange_codes SET used_at = ? WHERE id = ? AND used_at IS NULL')
    .run(now, row.id)

  if (consumed.changes !== 1) {
    throw new ExchangeCodeError('reused')
  }

  return { sessionId: row.session_id, attemptId: row.attempt_id }
}
