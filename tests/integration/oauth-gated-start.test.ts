import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-oauth-gated-test-'))
process.env.DATABASE_PATH = join(tmpDir, 'oauth-gated-test.db')
process.env.GROWTHBOOK_FEATURE_OVERRIDES = JSON.stringify({
  'm8:auth:dev_token_bootstrap': false,
})

describe('OAuth-gated session start', () => {
  let app: TestApp
  let closeDb: typeof import('../../src/db/connection.js').closeDb
  let getDb: typeof import('../../src/db/connection.js').getDb

  before(async () => {
    const { buildApp } = await import('../../src/index.js')
    ;({ closeDb, getDb } = await import('../../src/db/connection.js'))
    app = await buildApp()
  })

  after(async () => {
    await app.close()
    closeDb()
  })

  it('does not issue tokens from /v1/sessions/start when the dev bootstrap gate is off', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'unavailable-oauth.invalid' },
    })

    // The identifier cannot resolve, so OAuth initiation fails before any
    // session exists. The security contract is that the gate is OFF: no
    // tokens are ever issued from this path, whatever the failure status is.
    assert.equal(res.statusCode, 400)
    const body = JSON.parse(res.payload)
    assert.equal(body.code, 'IDENTITY_RESOLUTION_FAILED')
    assert.equal(Object.hasOwn(body, 'tokens'), false)
    const sessionCount = getDb().prepare('SELECT COUNT(*) AS count FROM sessions').get() as { count: number }
    assert.equal(sessionCount.count, 0)
  })
})
