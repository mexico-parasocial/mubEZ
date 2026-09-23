import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'

// Secure default: TRUST_PROXY_HEADERS is unset, so proxy headers must be
// ignored and every request from the same socket shares one bucket. Runs as
// its own process (node --test isolates per file) — the trusted mode has its
// own file, rate-limit-client-ip-trusted.test.ts.
const tmpDir = mkdtempSync(join(tmpdir(), 'm8-rate-client-ip-'))
process.env.DATABASE_PATH = join(tmpDir, 'rate-client-ip.db')
process.env.RATE_LIMIT_ENABLED = 'true'
process.env.RATE_LIMIT_AUTH_MAX = '3'

let app: TestApp
let closeDb: typeof import('../../src/db/connection.js').closeDb

function authRequest(ip: string | null) {
  return app.inject({
    method: 'POST',
    url: '/v1/sessions/start',
    headers: ip ? { 'x-forwarded-for': ip } : {},
    payload: { identifier: 'did:plc:rateclientip' },
  })
}

describe('rate limiter client IP (default: no proxy trust)', () => {
  before(async () => {
    const appModule = await import('../../src/index.js')
    const dbModule = await import('../../src/db/connection.js')
    app = await appModule.buildApp()
    closeDb = dbModule.closeDb
  })

  after(async () => {
    await app.close()
    closeDb()
  })

  it('does not let a rotating x-forwarded-for evade the auth bucket', async () => {
    for (let i = 0; i < 3; i++) {
      const res = await authRequest(`10.9.9.${i}`)
      assert.notEqual(res.statusCode, 429)
      assert.equal(res.headers['x-ratelimit-limit'], '3')
    }

    // A spoofed fresh header from the same socket must not buy a new bucket.
    const evaded = await authRequest('10.9.9.200')
    assert.equal(evaded.statusCode, 429)
    assert.equal(JSON.parse(evaded.payload).code, 'RATE_LIMIT_EXCEEDED')

    // x-real-ip alone is equally untrusted.
    const realIp = await authRequest('10.9.9.201')
    assert.equal(realIp.statusCode, 429)
  })
})
