import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-db-integrity-'))
process.env.DATABASE_PATH = join(tmpDir, 'db-integrity.db')

describe('database integrity guarantees', () => {
  let getDb: typeof import('../../src/db/connection.js').getDb
  let closeDb: typeof import('../../src/db/connection.js').closeDb

  before(async () => {
    ;({ getDb, closeDb } = await import('../../src/db/connection.js'))
    const { ensureSchema, runMigrations } = await import('../../src/db/migrate.js')
    ensureSchema()
    runMigrations()
  })

  after(() => {
    closeDb()
  })

  it('enforces one active session per DID while allowing revoked history', () => {
    const db = getDb()
    const now = new Date().toISOString()
    db.prepare(`
      INSERT INTO sessions
        (session_id, did, handle, display_name, authorization_server, authenticated_at, pds_safety_json, active_persona_id, active_surface_id, created_at, updated_at, status)
      VALUES (?, ?, ?, ?, ?, ?, '{}', 'orbit', 'public', ?, ?, ?)
    `).run('session-active-1', 'did:plc:dbintegrity', 'one.test', 'one.test', 'https://pds.test', now, now, now, 'active')

    assert.throws(() => {
      db.prepare(`
        INSERT INTO sessions
          (session_id, did, handle, display_name, authorization_server, authenticated_at, pds_safety_json, active_persona_id, active_surface_id, created_at, updated_at, status)
        VALUES (?, ?, ?, ?, ?, ?, '{}', 'orbit', 'public', ?, ?, ?)
      `).run('session-active-2', 'did:plc:dbintegrity', 'two.test', 'two.test', 'https://pds.test', now, now, now, 'active')
    }, /UNIQUE constraint failed/)

    db.prepare(`
      INSERT INTO sessions
        (session_id, did, handle, display_name, authorization_server, authenticated_at, pds_safety_json, active_persona_id, active_surface_id, created_at, updated_at, status)
      VALUES (?, ?, ?, ?, ?, ?, '{}', 'orbit', 'public', ?, ?, ?)
    `).run('session-revoked-1', 'did:plc:dbintegrity', 'old.test', 'old.test', 'https://pds.test', now, now, now, 'revoked')
  })

  it('enforces one non-terminal credential per commitment', () => {
    const db = getDb()
    const now = new Date().toISOString()
    db.prepare(`
      INSERT INTO grants
        (id, session_id, app_id, app_name, app_kind, surface, requested_claims_json, proof_mode, status, reason, requested_at)
      VALUES (?, ?, 'app', 'App', 'Verifier', 'civic', '[]', 'proof-only', 'approved', 'test', ?)
    `).run('grant-db-integrity', 'session-active-1', now)

    const insertProof = db.prepare(`
      INSERT INTO proof_artifacts
        (id, session_id, grant_id, claim_type, outcome, statement, audience_app_id, audience_app_name, surface, status, issued_at, revocation_hash, commitment)
      VALUES (?, 'session-active-1', 'grant-db-integrity', 'has_para_verification', 'verified', 'test', 'app', 'App', 'civic', ?, ?, ?, ?)
    `)

    insertProof.run('proof-active-1', 'active', now, 'revocation-a', '123456789')
    assert.throws(() => {
      insertProof.run('proof-active-2', 'active', now, 'revocation-b', '123456789')
    }, /UNIQUE constraint failed/)

    insertProof.run('proof-revoked-1', 'revoked', now, 'revocation-c', '123456789')
  })

  it('enforces unique revocation hashes and refresh replacement lineage', () => {
    const db = getDb()
    const now = new Date().toISOString()

    assert.throws(() => {
      db.prepare(`
        INSERT INTO proof_artifacts
          (id, session_id, grant_id, claim_type, outcome, statement, audience_app_id, audience_app_name, surface, status, issued_at, revocation_hash, commitment)
        VALUES (?, 'session-active-1', 'grant-db-integrity', 'has_para_verification', 'verified', 'test', 'app', 'App', 'civic', 'revoked', ?, ?, ?)
      `).run('proof-duplicate-revocation', now, 'revocation-a', '987654321')
    }, /UNIQUE constraint failed/)

    db.prepare(`
      INSERT INTO refresh_tokens
        (token_hash, session_id, expires_at, revoked_at, rotated_at, replaced_by_token_hash)
      VALUES (?, 'session-active-1', ?, ?, ?, ?)
    `).run('refresh-old-1', now, now, now, 'refresh-new')

    assert.throws(() => {
      db.prepare(`
        INSERT INTO refresh_tokens
          (token_hash, session_id, expires_at, revoked_at, rotated_at, replaced_by_token_hash)
        VALUES (?, 'session-active-1', ?, ?, ?, ?)
      `).run('refresh-old-2', now, now, now, 'refresh-new')
    }, /UNIQUE constraint failed/)
  })
})
