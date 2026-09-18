import { randomBytes } from 'node:crypto'
import { getDb } from '../db/connection.js'
import {
  verifyIdentityAssertion,
  type SignedAssertion,
} from './identitySignature.js'

/*
 * Identity registration (CRYPTO_DECISIONS.md CD-9).
 *
 * The client registers an identity by sending `identity_pub` and an sr25519
 * proof of possession (CD-7, purpose "mubez-registration") over a challenge the
 * server issued. The server verifies the proof and stores the key standalone —
 * no session, no seed, no link to another identity. See
 * `migrations/030_registered_identities.sql`.
 *
 * What this deliberately does NOT do:
 *  - It does not take a session id. Registration must not be correlated with a
 *    session (CD-9), so no code path here can accept or record one.
 *  - It does not register the ballot identity. `civic` never signs (OD-7
 *    Reading A); a `mubez-registration` proof it cannot produce cannot reach
 *    this service, and the signing allowlist upstream refuses it regardless.
 *  - It does not create burner identities. Those are deferred (CD-9, 2026-09-18)
 *    until the `/v2` per-community derivation exists.
 */

/**
 * The audience a registration proof must be bound to. A proof is signed over
 * its audience, so a signature minted for another verifier (e.g. para-idp's
 * `matrix-login`) cannot be replayed here even though it is the same key.
 */
export const REGISTRATION_AUDIENCE =
  process.env.M8_REGISTRATION_AUDIENCE?.trim() || 'mubez'

const CHALLENGE_MAX_AGE_MS = 5 * 60 * 1000

/** Issue a fresh, single-use, session-unbound registration challenge. */
export function issueRegistrationChallenge(): string {
  const challenge = randomBytes(32).toString('base64url')
  // Store created_at as an explicit ISO string rather than leaning on the SQL
  // DEFAULT: freshness is security-relevant here, and SQLite's datetime('now')
  // is a space-separated form that Date.parse handles inconsistently.
  getDb()
    .prepare(
      'INSERT INTO identity_registration_challenges (challenge, created_at) VALUES (?, ?)',
    )
    .run(challenge, new Date().toISOString())
  return challenge
}

export type RegistrationResult =
  | { ok: true; alreadyRegistered: boolean }
  | { ok: false; reason: 'bad-challenge' | 'bad-proof' }

/**
 * Register an identity from a signed proof of possession.
 *
 * Fail-closed at every step, and never throws on attacker input:
 *  - an unknown, stale, or already-consumed challenge is `bad-challenge`
 *    before any signature work;
 *  - a proof that does not verify against the presented `identity_pub` and the
 *    outstanding challenge is `bad-proof`;
 *  - the challenge is consumed only on a verified proof, so a failed attempt
 *    does not burn it, but a verified one cannot be replayed.
 *
 * Re-registering a key already on file is a no-op success (`alreadyRegistered`):
 * the key is stored standalone, so a duplicate carries no new information and
 * nothing is overwritten.
 */
export function registerIdentity(
  signed: SignedAssertion,
  now: Date = new Date(),
): RegistrationResult {
  const challenge = signed?.assertion?.challenge
  if (typeof challenge !== 'string' || challenge.length === 0) {
    return { ok: false, reason: 'bad-challenge' }
  }

  const db = getDb()
  const row = db
    .prepare(
      'SELECT created_at AS createdAt, consumed_at AS consumedAt FROM identity_registration_challenges WHERE challenge = ?',
    )
    .get(challenge) as { createdAt: string; consumedAt: string | null } | undefined

  if (!row || row.consumedAt) return { ok: false, reason: 'bad-challenge' }
  const createdAt = Date.parse(row.createdAt)
  if (Number.isNaN(createdAt) || now.getTime() - createdAt > CHALLENGE_MAX_AGE_MS) {
    return { ok: false, reason: 'bad-challenge' }
  }

  const verified = verifyIdentityAssertion(signed, {
    purpose: 'mubez-registration',
    audience: REGISTRATION_AUDIENCE,
    challenge,
    now,
  })
  if (!verified) return { ok: false, reason: 'bad-proof' }

  const identityPub = signed.assertion.identityPub
  // Consume the challenge and store the key in one transaction: a verified
  // proof must never leave the challenge replayable, and must never half-apply.
  const consume = db.transaction(() => {
    const consumed = db
      .prepare(
        "UPDATE identity_registration_challenges SET consumed_at = ? WHERE challenge = ? AND consumed_at IS NULL",
      )
      .run(now.toISOString(), challenge)
    // Lost the race to consume it — another request already did. Treat as a
    // spent challenge rather than registering off an already-consumed proof.
    if (consumed.changes !== 1) return false
    const inserted = db
      .prepare(
        'INSERT OR IGNORE INTO registered_identities (identity_pub) VALUES (?)',
      )
      .run(identityPub)
    return { alreadyRegistered: inserted.changes === 0 }
  })

  const outcome = consume()
  if (outcome === false) return { ok: false, reason: 'bad-challenge' }
  return { ok: true, alreadyRegistered: outcome.alreadyRegistered }
}

/** Whether a public key has been registered. */
export function isIdentityRegistered(identityPub: string): boolean {
  const row = getDb()
    .prepare('SELECT 1 FROM registered_identities WHERE identity_pub = ?')
    .get(identityPub)
  return !!row
}
