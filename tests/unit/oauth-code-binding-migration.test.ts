import { it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import Database from 'better-sqlite3'

it('backfills outstanding verifier bindings, preserves legacy clients and invalidates unbound orphan codes', () => {
  const db = new Database(':memory:')
  try {
    db.exec(`
      CREATE TABLE oauth_login_attempts (id TEXT PRIMARY KEY, exchange_challenge TEXT);
      CREATE TABLE oauth_exchange_codes (attempt_id TEXT, used_at TEXT);
      INSERT INTO oauth_login_attempts VALUES ('para', 'challenge'), ('legacy', NULL);
      INSERT INTO oauth_exchange_codes VALUES ('para', NULL), ('legacy', NULL), ('orphan', NULL);
    `)
    db.exec(
      readFileSync(new URL('../../src/db/migrations/041_oauth_code_binding_retention.sql', import.meta.url), 'utf8'),
    )
    const rows = db.prepare('SELECT * FROM oauth_exchange_codes ORDER BY attempt_id').all() as {
      attempt_id: string
      used_at: string | null
      exchange_challenge: string | null
    }[]
    assert.deepEqual(
      rows.find((row) => row.attempt_id === 'para'),
      { attempt_id: 'para', used_at: null, exchange_challenge: 'challenge' },
    )
    assert.deepEqual(
      rows.find((row) => row.attempt_id === 'legacy'),
      { attempt_id: 'legacy', used_at: null, exchange_challenge: null },
    )
    assert.ok(rows.find((row) => row.attempt_id === 'orphan')?.used_at)
  } finally {
    db.close()
  }
})
