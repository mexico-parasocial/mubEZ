import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-assurance-replay-'))
process.env.DATABASE_PATH = join(tmpDir, 'assurance-replay.db')

/**
 * CD-10: the shared replay-consume primitive must hold the same properties the
 * reviewed PDS m8-assurance-store holds — single-use nonce, jti that cannot spend
 * a second nonce (with rollback), expiry, binding match, and a pending cap.
 */
describe('assurance replay store (CD-10)', () => {
  let store: typeof import('../../src/services/assuranceReplayStore.js')
  let closeDb: typeof import('../../src/db/connection.js').closeDb

  const ISSUER = 'mubez'
  const bindings = (subject: string, binding: string) => ({ subject, binding })
  const B = bindings('id-pub-aaa', 'audience=mubez|action=create')

  // A controllable clock.
  let clock = new Date('2026-09-18T12:00:00.000Z')
  const now = () => clock
  const advance = (sec: number) => {
    clock = new Date(clock.getTime() + sec * 1000)
  }

  before(async () => {
    const conn = await import('../../src/db/connection.js')
    closeDb = conn.closeDb
    const { ensureSchema, runMigrations } = await import('../../src/db/migrate.js')
    ensureSchema()
    runMigrations()
    store = await import('../../src/services/assuranceReplayStore.js')
  })

  after(() => closeDb())

  it('issues then consumes a challenge exactly once', () => {
    const { nonce } = store.issueChallenge(B, ISSUER, now)
    assert.equal(
      store.consumeChallenge({ nonce, jti: 'jti-1', bindings: B, issuer: ISSUER }, now),
      true,
    )
    // Replaying the same nonce (with a fresh jti) fails: it is already spent.
    assert.equal(
      store.consumeChallenge({ nonce, jti: 'jti-1b', bindings: B, issuer: ISSUER }, now),
      false,
    )
  })

  it('rejects a replayed jti, and rolls back so it cannot spend a fresh nonce', () => {
    const first = store.issueChallenge(B, ISSUER, now)
    assert.equal(
      store.consumeChallenge({ nonce: first.nonce, jti: 'shared-jti', bindings: B, issuer: ISSUER }, now),
      true,
    )
    // A second, valid, unspent nonce — but the same jti.
    const second = store.issueChallenge(B, ISSUER, now)
    assert.equal(
      store.consumeChallenge({ nonce: second.nonce, jti: 'shared-jti', bindings: B, issuer: ISSUER }, now),
      false,
    )
    // The rollback must have kept the second nonce unspent: a different jti works.
    assert.equal(
      store.consumeChallenge({ nonce: second.nonce, jti: 'other-jti', bindings: B, issuer: ISSUER }, now),
      true,
    )
  })

  it('rejects an expired challenge', () => {
    const { nonce } = store.issueChallenge(B, ISSUER, now)
    advance(store.ASSURANCE_MAX_LIFETIME_SEC + 1)
    assert.equal(
      store.consumeChallenge({ nonce, jti: 'jti-exp', bindings: B, issuer: ISSUER }, now),
      false,
    )
  })

  it('rejects a binding mismatch (nonce not issued for these bindings)', () => {
    const { nonce } = store.issueChallenge(B, ISSUER, now)
    const tampered = bindings(B.subject, 'audience=mubez|action=delete')
    assert.equal(
      store.consumeChallenge({ nonce, jti: 'jti-bind', bindings: tampered, issuer: ISSUER }, now),
      false,
    )
    // Wrong issuer is also rejected.
    assert.equal(
      store.consumeChallenge({ nonce, jti: 'jti-iss', bindings: B, issuer: 'someone-else' }, now),
      false,
    )
  })

  it('rejects an unknown nonce', () => {
    assert.equal(
      store.consumeChallenge({ nonce: 'never-issued', jti: 'jti-x', bindings: B, issuer: ISSUER }, now),
      false,
    )
  })

  it('caps pending challenges per subject', () => {
    const subject = 'id-pub-capped'
    const capBindings = bindings(subject, 'audience=mubez|action=create')
    for (let i = 0; i < store.MAX_PENDING_CHALLENGES_PER_SUBJECT; i++) {
      store.issueChallenge(capBindings, ISSUER, now)
    }
    assert.throws(() => store.issueChallenge(capBindings, ISSUER, now), /TooManyChallenges|pending/i)
  })

  it('cleanup drops expired challenges and stale receipts', () => {
    const before = store.issueChallenge(bindings('id-pub-clean', 'x'), ISSUER, now)
    store.consumeChallenge({ nonce: before.nonce, jti: 'jti-clean', bindings: bindings('id-pub-clean', 'x'), issuer: ISSUER }, now)
    advance(store.ASSURANCE_MAX_LIFETIME_SEC + store.ASSURANCE_CLOCK_TOLERANCE_SEC + 10)
    const removed = store.cleanupExpired(now)
    assert.ok(removed.challenges >= 1)
    assert.ok(removed.receipts >= 1)
  })
})
