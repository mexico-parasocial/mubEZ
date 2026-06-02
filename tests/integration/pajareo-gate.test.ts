import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SignJWT } from 'jose'
import type { TestApp } from '../helpers/testApp.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-pajareo-gate-test-'))
process.env.DATABASE_PATH = join(tmpDir, 'pajareo-gate-test.db')
process.env.JWT_SECRET = 'pajareo-gate-test-secret-minimum-32-chars'
process.env.GROWTHBOOK_FEATURE_OVERRIDES = JSON.stringify({
  'm8:pajareo:enable': false,
})

describe('Pajareo feature gate', () => {
  let app: TestApp
  let accessToken: string

  before(async () => {
    const { buildApp } = await import('../../src/index.js')
    app = await buildApp()
    accessToken = await seedSession('gated-session', 'did:plc:pajareo-gated')
  })

  after(async () => {
    await app.close()
  })

  it('returns an empty public feed and blocks mutations when disabled', async () => {
    const publicFeed = await app.inject({
      method: 'GET',
      url: '/v1/pajareo/representatives/fed_exec_1',
    })
    assert.equal(publicFeed.statusCode, 200)
    assert.deepEqual(JSON.parse(publicFeed.payload), {
      representativeId: 'fed_exec_1',
      entries: [],
    })

    const create = await app.inject({
      method: 'POST',
      url: '/v1/pajareo/representatives/fed_exec_1/entries',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        type: 'pregunta',
        body: 'Should be gated.',
      },
    })
    assert.equal(create.statusCode, 404)
    assert.equal(JSON.parse(create.payload).code, 'FEATURE_DISABLED')
  })
})

async function seedSession(sessionId: string, did: string) {
  const { getDb } = await import('../../src/db/connection.js')
  const now = new Date().toISOString()
  getDb().prepare(`
    INSERT INTO sessions
      (session_id, did, handle, display_name, authorization_server, authenticated_at, pds_safety_json, active_persona_id, active_surface_id, oauth_scope, created_at, updated_at, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    sessionId,
    did,
    did,
    did,
    'https://pds.test',
    now,
    '{}',
    'orbit',
    'public',
    'atproto',
    now,
    now,
    'active',
  )

  const seconds = Math.floor(Date.now() / 1000)
  return new SignJWT({ type: 'access' })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setSubject(sessionId)
    .setIssuer(process.env.JWT_ISSUER ?? 'mubez')
    .setAudience(process.env.JWT_AUDIENCE ?? 'm8.api')
    .setIssuedAt(seconds)
    .setExpirationTime(seconds + 86400)
    .sign(new TextEncoder().encode(process.env.JWT_SECRET))
}
