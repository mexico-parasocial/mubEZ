import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-test-'))
process.env.DATABASE_PATH = join(tmpDir, 'ledger-test.db')

describe('ledger integration', () => {
  let app: TestApp
  let accessToken: string

  before(async () => {
    const { buildApp } = await import('../../src/index.js')
    app = await buildApp()
    const start = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'ledgeruser.bsky.social' },
    })
    const body = JSON.parse(start.payload)
    accessToken = body.tokens.accessToken
  })

  after(async () => {
    await app.close()
  })

  it('GET /v1/ledger returns audit trail for the session', async () => {
    // Create a grant (which writes a ledger entry)
    const create = await app.inject({
      method: 'POST',
      url: '/v1/grants',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        appId: 'ledger.app',
        appName: 'Ledger App',
        appKind: 'Consumer app',
        surface: 'public',
        requestedClaims: [{ type: 'has_para_verification', disclosure: 'proof-only' }],
        proofMode: 'proof-only',
        reason: 'Testing ledger audit trail',
      },
    })
    const { grant } = JSON.parse(create.payload)

    // Fetch ledger
    const res = await app.inject({
      method: 'GET',
      url: '/v1/ledger',
      headers: { authorization: `Bearer ${accessToken}` },
    })

    assert.equal(res.statusCode, 200)
    const body = JSON.parse(res.payload)
    assert.ok(Array.isArray(body.ledger))
    assert.equal(body.ledger.length, 2)
    assert.ok(body.ledger.some((entry: { action: string }) => entry.action === 'TokenIssued'))
    const requested = body.ledger.find((entry: { action: string }) => entry.action === 'Requested')
    assert.ok(requested)
    assert.equal(requested.targetType, 'grant')
    assert.ok(body.grants)
    assert.equal(body.grants.length, 1)
    assert.equal(body.grants[0].appName, 'Ledger App')
    assert.equal(body.summary.totalRequests, 1)

    // Approve and check ledger grows
    await app.inject({
      method: 'POST',
      url: `/v1/grants/${grant.id}/approve`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { grantId: grant.id },
    })

    const res2 = await app.inject({
      method: 'GET',
      url: '/v1/ledger',
      headers: { authorization: `Bearer ${accessToken}` },
    })
    const body2 = JSON.parse(res2.payload)
    assert.equal(body2.ledger.length, 3)
    assert.ok(body2.ledger.some((entry: { action: string }) => entry.action === 'Approved'))
    assert.equal(body2.summary.activeGrants, 1)
  })

  it('GET /v1/ledger requires auth', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/ledger',
    })
    assert.equal(res.statusCode, 401)
  })
})
