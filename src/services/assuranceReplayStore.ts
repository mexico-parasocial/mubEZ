import { createHash, randomBytes } from 'node:crypto'
import { getDb } from '../db/connection.js'

/*
 * The broker's shared replay-consume primitive (CRYPTO_DECISIONS.md CD-10).
 *
 * One implementation, used by every assurance role mubEZ owns. It is a faithful
 * port of the reviewed PDS primitive
 * (WatZappa-permissioned-data/packages/pds/src/account-manager/m8-assurance-store.ts):
 * a server-issued single-use challenge plus a client one-time id (jti), consumed
 * atomically. The load-bearing detail is the double guard — the nonce is marked
 * spent AND the jti is recorded in one transaction, and if the jti was already
 * used the whole thing rolls back, so a replayed jti can never spend a fresh
 * nonce and a replayed nonce can never re-run.
 *
 * Storage layers differ across the repos (better-sqlite3 here, kysely on the
 * PDS), so what is shared is the algorithm, not the code; the PDS store is the
 * reference behaviour and the tests here assert the same properties.
 *
 * Bindings are opaque to this store: callers hash whatever the proof commits to
 * (audience, identity_pub, action, purpose, …) into `bindingHash`, and consume
 * must present the identical bindings. This store never sees a session id.
 */

/** Seconds a challenge is valid for. Matches the PDS M8_ASSURANCE_MAX_LIFETIME. */
export const ASSURANCE_MAX_LIFETIME_SEC = 60
/** Clock skew tolerance for retaining jti receipts. */
export const ASSURANCE_CLOCK_TOLERANCE_SEC = 5
/** Cap on outstanding, unexpired challenges per subject, to bound abuse. */
export const MAX_PENDING_CHALLENGES_PER_SUBJECT = 10

function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex')
}

function nowSec(now: () => Date): number {
  return Math.floor(now().getTime() / 1000)
}

export type ChallengeBindings = {
  /** The subject the pending-count cap is scoped to (e.g. identity_pub). */
  subject: string
  /** Canonical, already-serialized bindings the nonce is issued for. */
  binding: string
}

/**
 * Issue a single-use challenge. Returns the raw nonce (shown once) and its
 * expiry. Throws if the subject has too many pending challenges.
 */
export function issueChallenge(
  bindings: ChallengeBindings,
  issuer: string,
  now: () => Date = () => new Date(),
): { nonce: string; expiresAt: number } {
  const db = getDb()
  const run = db.transaction(() => {
    const t = nowSec(now)
    const { count } = db
      .prepare(
        'SELECT COUNT(*) AS count FROM assurance_challenge WHERE subject = ? AND consumed_at IS NULL AND expires_at > ?',
      )
      .get(bindings.subject, t) as { count: number }
    if (count >= MAX_PENDING_CHALLENGES_PER_SUBJECT) {
      throw new TooManyChallengesError()
    }
    const nonce = randomBytes(32).toString('base64url')
    const expiresAt = t + ASSURANCE_MAX_LIFETIME_SEC
    db.prepare(
      'INSERT INTO assurance_challenge (nonce_hash, subject, binding_hash, issuer, issued_at, expires_at, consumed_at) VALUES (?, ?, ?, ?, ?, ?, NULL)',
    ).run(digest(nonce), bindings.subject, digest(bindings.binding), issuer, t, expiresAt)
    return { nonce, expiresAt }
  })
  return run()
}

/**
 * Consume a challenge after the signature and all bindings have been verified.
 * Returns true exactly once for a valid (nonce, jti, bindings) triple; false for
 * an unknown/expired/already-consumed nonce, a mismatched binding, or a replayed
 * jti. Never throws on a spent credential — only on an unexpected DB error.
 */
export function consumeChallenge(
  input: { nonce: string; jti: string; bindings: ChallengeBindings; issuer: string },
  now: () => Date = () => new Date(),
): boolean {
  const db = getDb()
  try {
    const run = db.transaction(() => {
      const t = nowSec(now)
      const spent = db
        .prepare(
          `UPDATE assurance_challenge SET consumed_at = ?
             WHERE nonce_hash = ? AND binding_hash = ? AND issuer = ? AND subject = ?
               AND issued_at <= ? AND expires_at > ? AND consumed_at IS NULL`,
        )
        .run(
          t,
          digest(input.nonce),
          digest(input.bindings.binding),
          input.issuer,
          input.bindings.subject,
          t,
          t,
        )
      if (spent.changes !== 1) return false

      const receipt = db
        .prepare(
          'INSERT OR IGNORE INTO assurance_receipt (issuer, jti_hash, consumed_at, retain_until) VALUES (?, ?, ?, ?)',
        )
        .run(input.issuer, digest(input.jti), t, t + ASSURANCE_CLOCK_TOLERANCE_SEC + ASSURANCE_MAX_LIFETIME_SEC)
      // The jti already spent another nonce: roll back this nonce's consumption.
      if (receipt.changes !== 1) throw new ReplayedJtiError()
      return true
    })
    return run()
  } catch (err) {
    if (err instanceof ReplayedJtiError) return false
    throw err
  }
}

/** Bounded maintenance: drop consumed/expired challenges and stale receipts. */
export function cleanupExpired(now: () => Date = () => new Date()): {
  challenges: number
  receipts: number
} {
  const db = getDb()
  const t = nowSec(now)
  const challenges = db
    .prepare('DELETE FROM assurance_challenge WHERE expires_at <= ? OR consumed_at IS NOT NULL')
    .run(t).changes
  const receipts = db
    .prepare('DELETE FROM assurance_receipt WHERE retain_until <= ?')
    .run(t).changes
  return { challenges, receipts }
}

export class TooManyChallengesError extends Error {
  readonly statusCode = 429
  readonly code = 'TOO_MANY_CHALLENGES'
  constructor() {
    super('Too many pending challenges')
    this.name = 'TooManyChallengesError'
  }
}

class ReplayedJtiError extends Error {}
