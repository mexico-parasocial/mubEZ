import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'

// Opt-in mode: TRUST_PROXY_HEADERS=true, as behind a reverse proxy that
// overwrites x-forwarded-for. Runs as its own process (node --test isolates
// per file) so the flag cannot leak into the default-mode test.
const tmpDir = mkdtempSync(join(tmpdir(), 'm8-rate-client-ip-trusted-'))
process.env.DATABASE_PATH = join(tmpDir, 'rate-client-ip-trusted.db')
process.env.RATE_LIMIT_ENABLED = 'true'
process.env.RATE_LIMIT_AUTH_MAX = '2'
process.env.TRUST_PROXY_HEADERS = 'true'

let app: TestApp
let closeDb: typeof import('../../src/db/connection.js').closeDb

function authRequest(forwardedFor: string) {
  return app.inject({
    method: 'POST',
    url: '/v1/sessions/start',
    headers: { 'x-forwarded-for': forwardedFor },
    payload: { identifier: 'did:plc:ratetrustedip' },
  })
}

describe('rate limiter client IP (TRUST_PROXY_HEADERS=true)', () => {
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

  it('keys the auth bucket on the forwarded client when trust is enabled', async () => {
    // Distinct forwarded clients, each with their own budget.
    for (let i = 0; i < 3; i++) {
      const res = await authRequest(`10.4.4.${i}`)
      assert.notEqual(res.statusCode, 429)
      assert.equal(res.headers['x-ratelimit-limit'], '2')
    }

    // One forwarded client exhausts its own bucket and only its own.
    const first = await authRequest('10.4.4.50')
    assert.notEqual(first.statusCode, 429)
    const second = await authRequest('10.4.4.50')
    assert.notEqual(second.statusCode, 429)
    const limited = await authRequest('10.4.4.50')
    assert.equal(limited.statusCode, 429)

    // The rightmost hop is the one the trusted proxy appended; a client-sent
    // prefix does not change who is being counted.
    const spoofedPrefix = await authRequest('1.2.3.4, 10.4.4.50')
    assert.equal(spoofedPrefix.statusCode, 429)
    const otherClient = await authRequest('1.2.3.4, 10.4.4.51')
    assert.notEqual(otherClient.statusCode, 429)
  })
})
