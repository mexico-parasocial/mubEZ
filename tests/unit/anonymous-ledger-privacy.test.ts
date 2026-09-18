import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-anon-ledger-'))
process.env.DATABASE_PATH = join(tmpDir, 'anon-ledger.db')

/**
 * D2 (F2b): the account ledger must not record a row relating a session to a
 * specific anonymous identity, post, or profile — that relation is the linkage
 * the threat model forbids, and it leaked through GET /v1/ledger. This pins the
 * absence: exercising the anonymous surface writes no such ledger row.
 */
describe('anonymous actions leave no session-linked ledger row (D2)', () => {
  let getDb: typeof import('../../src/db/connection.js').getDb
  let closeDb: typeof import('../../src/db/connection.js').closeDb
  let anon: typeof import('../../src/services/anonymousIdentityService.js')

  const SESSION = 'session-anon-ledger'

  before(async () => {
    ;({ getDb, closeDb } = await import('../../src/db/connection.js'))
    const { ensureSchema, runMigrations } = await import('../../src/db/migrate.js')
    ensureSchema()
    runMigrations()
    anon = await import('../../src/services/anonymousIdentityService.js')

    const now = new Date().toISOString()
    getDb()
      .prepare(`
        INSERT INTO sessions
          (session_id, did, handle, display_name, authorization_server, authenticated_at, pds_safety_json, active_persona_id, active_surface_id, created_at, updated_at, status)
        VALUES (?, ?, ?, ?, ?, ?, '{}', 'orbit', 'public', ?, ?, 'active')
      `)
      .run(SESSION, 'did:plc:anonledger', 'anon.test', 'anon.test', 'https://pds.test', now, now, now)
  })

  after(() => closeDb())

  it('creating, updating, and posting from an anonymous identity writes no ledger row', () => {
    const db = getDb()
    const before = (db.prepare('SELECT COUNT(*) AS n FROM ledger').get() as { n: number }).n

    const identity = anon.createAnonymousIdentity(SESSION, { displayName: 'No Ledger' })
    anon.updateAnonymousIdentity(SESSION, identity.id, { displayName: 'Renamed' })
    anon.linkAnonymousPost(SESSION, {
      identityId: identity.id,
      postUri: 'at://did:plc:anonledger/app.bsky.feed.post/abc',
    })

    const after = (db.prepare('SELECT COUNT(*) AS n FROM ledger').get() as { n: number }).n
    assert.equal(after, before, 'anonymous-surface actions must not write ledger rows')

    // And specifically: no ledger row anywhere names an anonymous target.
    const anonRows = (
      db
        .prepare(
          "SELECT COUNT(*) AS n FROM ledger WHERE target_type IN ('anonymous_identity','anonymous_identity_post','anonymous_profile')",
        )
        .get() as { n: number }
    ).n
    assert.equal(anonRows, 0)
  })
})
