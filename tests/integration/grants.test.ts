import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-test-'))
process.env.DATABASE_PATH = join(tmpDir, 'test.db')

let buildApp: typeof import('../../src/index.js').buildApp
let closeDb: typeof import('../../src/db/connection.js').closeDb

describe('grants integration', () => {
  let app: TestApp
  let accessToken: string

  before(async () => {
    ;({ buildApp } = await import('../../src/index.js'))
    ;({ closeDb } = await import('../../src/db/connection.js'))
    app = await buildApp()
    const start = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'grantuser.bsky.social' },
    })
    const body = JSON.parse(start.payload)
    accessToken = body.tokens.accessToken
  })

  after(async () => {
    await app.close()
    closeDb()
  })

  it('POST /v1/grants creates a grant request', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/grants',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        appId: 'test.app',
        appName: 'Test App',
        appKind: 'Consumer app',
        surface: 'public',
        requestedClaims: [{ type: 'has_para_verification', disclosure: 'proof-only' }],
        proofMode: 'proof-only',
        reason: 'Testing grant request',
      },
    })

    assert.equal(res.statusCode, 201)
    const body = JSON.parse(res.payload)
    assert.equal(body.grant.status, 'pending')
    assert.equal(body.grant.appId, 'test.app')
  })

  it('POST /v1/grants/:id/approve approves a grant', async () => {
    const create = await app.inject({
      method: 'POST',
      url: '/v1/grants',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        appId: 'test.app',
        appName: 'Test App',
        appKind: 'Consumer app',
        surface: 'public',
        requestedClaims: [{ type: 'has_para_verification', disclosure: 'proof-only' }],
        proofMode: 'proof-only',
        reason: 'Testing approval',
      },
    })
    const { grant } = JSON.parse(create.payload)

    const res = await app.inject({
      method: 'POST',
      url: `/v1/grants/${grant.id}/approve`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { grantId: grant.id, reviewNote: 'Looks good' },
    })

    assert.equal(res.statusCode, 200)
    const body = JSON.parse(res.payload)
    assert.equal(body.grant.status, 'approved')
    assert.ok(body.proofs.length > 0)
  })

  it('approves bounded party-tenure governance proofs without raw join dates', async () => {
    const create = await app.inject({
      method: 'POST',
      url: '/v1/grants',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        appId: 'para.governance',
        appName: 'PARA Governance',
        appKind: 'Civic app',
        surface: 'civic',
        requestedClaims: [
          {
            type: 'joined_during_founding_period',
            disclosure: 'proof-only',
            requestedValue: 'partido-migala',
          },
          {
            type: 'has_continuous_party_membership_30d',
            disclosure: 'proof-only',
            requestedValue: 'partido-migala',
          },
        ],
        proofMode: 'proof-only',
        reason: 'Horizontal governance role eligibility',
      },
    })
    assert.equal(create.statusCode, 201)
    const { grant } = JSON.parse(create.payload)

    const approve = await app.inject({
      method: 'POST',
      url: `/v1/grants/${grant.id}/approve`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { grantId: grant.id, reviewNote: 'Governance proofs approved' },
    })

    assert.equal(approve.statusCode, 200)
    const body = JSON.parse(approve.payload)
    assert.equal(body.proofs.length, 2)
    assert.deepEqual(
      body.proofs.map((proof: { claimType: string; outcome: string }) => [
        proof.claimType,
        proof.outcome,
      ]),
      [
        ['joined_during_founding_period', 'bounded'],
        ['has_continuous_party_membership_30d', 'bounded'],
      ],
    )
    assert.ok(
      body.proofs.every((proof: { statement: string }) =>
        !/\d{4}-\d{2}-\d{2}/.test(proof.statement),
      ),
    )
  })

  it('POST /v1/grants/:id/revoke revokes a grant', async () => {
    const create = await app.inject({
      method: 'POST',
      url: '/v1/grants',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        appId: 'revoke.app',
        appName: 'Revoke App',
        appKind: 'Consumer app',
        surface: 'public',
        requestedClaims: [{ type: 'has_para_verification', disclosure: 'proof-only' }],
        proofMode: 'proof-only',
        reason: 'Testing revoke',
      },
    })
    const { grant } = JSON.parse(create.payload)

    const res = await app.inject({
      method: 'POST',
      url: `/v1/grants/${grant.id}/revoke`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { grantId: grant.id, reason: 'User requested' },
    })

    assert.equal(res.statusCode, 200)
    const body = JSON.parse(res.payload)
    assert.equal(body.grant.status, 'revoked')
  })
})
