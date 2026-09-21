import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-oauth-exchange-'))
process.env.DATABASE_PATH = join(tmpDir, 'oauth-exchange.db')

describe('oauth exchange codes', () => {
  let createExchangeCode: typeof import('../../src/services/oauthExchangeCodes.js').createExchangeCode
  let consumeExchangeCode: typeof import('../../src/services/oauthExchangeCodes.js').consumeExchangeCode
  let ExchangeCodeError: typeof import('../../src/services/oauthExchangeCodes.js').ExchangeCodeError
  let getDb: typeof import('../../src/db/connection.js').getDb
  let closeDb: typeof import('../../src/db/connection.js').closeDb

  before(async () => {
    ;({ getDb, closeDb } = await import('../../src/db/connection.js'))
    const { ensureSchema, runMigrations } = await import('../../src/db/migrate.js')
    ensureSchema()
    runMigrations()
    ;({ createExchangeCode, consumeExchangeCode, ExchangeCodeError } = await import(
      '../../src/services/oauthExchangeCodes.js'
    ))
  })

  after(() => {
    closeDb()
  })

  function kindOf(fn: () => unknown): string {
    try {
      fn()
      return 'ok'
    } catch (error) {
      return error instanceof ExchangeCodeError ? error.kind : `unexpected: ${String(error)}`
    }
  }

  it('round-trips: consume returns the bound session and attempt, then is single-use', () => {
    const { code } = createExchangeCode({ attemptId: 'attempt-1', sessionId: 'session-1' })

    const consumed = consumeExchangeCode(code)
    assert.equal(consumed.sessionId, 'session-1')
    assert.equal(consumed.attemptId, 'attempt-1')

    assert.equal(kindOf(() => consumeExchangeCode(code)), 'reused')
  })

  it('rejects unknown codes with the same error as forged ones', () => {
    assert.equal(kindOf(() => consumeExchangeCode('m8ex-does-not-exist')), 'invalid')
  })

  it('rejects expired codes indistinguishably from unknown ones', () => {
    const { code } = createExchangeCode({ attemptId: 'attempt-2', sessionId: 'session-2' })
    getDb()
      .prepare("UPDATE oauth_exchange_codes SET expires_at = '2000-01-01T00:00:00.000Z'")
      .run()

    // Expired rows are pruned on read, so clients see the same 'invalid' as a
    // forged code — no oracle about which codes ever existed.
    assert.equal(kindOf(() => consumeExchangeCode(code)), 'invalid')
  })

  it('stores only a hash of the code, never the plaintext', () => {
    const { code } = createExchangeCode({ attemptId: 'attempt-3', sessionId: 'session-3' })

    const rows = getDb()
      .prepare('SELECT code_hash FROM oauth_exchange_codes')
      .all() as { code_hash: string }[]

    assert.ok(rows.length >= 1)
    for (const row of rows) {
      assert.ok(!row.code_hash.includes(code), 'plaintext code must not be stored')
      assert.match(row.code_hash, /^[0-9a-f]{64}$/, 'stored value must be a sha-256 hex digest')
    }
  })

  it('replay loses the race even when consumption is concurrent-looking', () => {
    const { code } = createExchangeCode({ attemptId: 'attempt-4', sessionId: 'session-4' })

    const first = consumeExchangeCode(code)
    assert.equal(first.sessionId, 'session-4')
    assert.equal(kindOf(() => consumeExchangeCode(code)), 'reused')
    assert.equal(kindOf(() => consumeExchangeCode(code)), 'reused')
  })
})
