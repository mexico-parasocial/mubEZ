import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-community-rate-test-'))
process.env.DATABASE_PATH = join(tmpDir, 'community-rate-test.db')
process.env.RATE_LIMIT_ENABLED = 'true'
process.env.RATE_LIMIT_COMMUNITY_READ_MAX = '4'
process.env.RATE_LIMIT_COMMUNITY_MUTATION_MAX = '2'
process.env.RATE_LIMIT_COMMUNITY_VOTE_MAX = '1'

let app: TestApp
let closeDb: typeof import('../../src/db/connection.js').closeDb

async function startSession() {
  const res = await app.inject({
    method: 'POST',
    url: '/v1/sessions/start',
    payload: { identifier: 'did:plc:rateadmin' },
  })
  assert.equal(res.statusCode, 200)
  return JSON.parse(res.payload).tokens.accessToken as string
}

describe('community governance rate limits', () => {
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

  it('limits community mutations by category while allowing the higher read budget', async () => {
    const token = await startSession()

    for (let i = 0; i < 4; i++) {
      const read = await app.inject({
        method: 'GET',
        url: '/v1/communities',
        headers: { authorization: `Bearer ${token}` },
      })
      assert.equal(read.statusCode, 200)
      assert.equal(read.headers['x-ratelimit-limit'], '4')
    }

    for (let i = 0; i < 2; i++) {
      const create = await app.inject({
        method: 'POST',
        url: '/v1/communities',
        headers: { authorization: `Bearer ${token}` },
        payload: {
          did: `did:web:rate-${i}.test`,
          name: `Rate ${i}`,
          description: 'Rate limit test',
        },
      })
      assert.equal(create.statusCode, 201)
      assert.equal(create.headers['x-ratelimit-limit'], '2')
    }

    const limited = await app.inject({
      method: 'POST',
      url: '/v1/communities',
      headers: { authorization: `Bearer ${token}` },
      payload: {
        did: 'did:web:rate-limited.test',
        name: 'Rate limited',
        description: 'Rate limit test',
      },
    })
    assert.equal(limited.statusCode, 429)
    assert.equal(JSON.parse(limited.payload).code, 'RATE_LIMIT_EXCEEDED')

    const votePayload = {
      vote: 'approve',
      signature: 'invalid',
      signedAt: new Date().toISOString(),
      nonce: Buffer.alloc(16, 1).toString('base64url'),
    }
    const firstVoteAttempt = await app.inject({
      method: 'POST',
      url: '/v1/communities/community-rate/actions/action-rate/vote',
      headers: { authorization: `Bearer ${token}` },
      payload: votePayload,
    })
    assert.notEqual(firstVoteAttempt.statusCode, 429)
    assert.equal(firstVoteAttempt.headers['x-ratelimit-limit'], '1')

    const secondVoteAttempt = await app.inject({
      method: 'POST',
      url: '/v1/communities/community-rate/actions/action-rate/vote',
      headers: { authorization: `Bearer ${token}` },
      payload: { ...votePayload, nonce: Buffer.alloc(16, 2).toString('base64url') },
    })
    assert.equal(secondVoteAttempt.statusCode, 429)
    assert.equal(JSON.parse(secondVoteAttempt.payload).code, 'RATE_LIMIT_EXCEEDED')
  })
})
