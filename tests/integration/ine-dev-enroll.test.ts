import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-ine-dev-enroll-test-'))
process.env.CIVIC_VOTE_PROOF_SECRET = 'test-only-civic-authorization-secret-2026'
process.env.DATABASE_PATH = join(tmpDir, 'ine-dev-enroll-test.db')

const subjectUri = 'at://did:plc:example/com.para.civic.cabildeo/dev-enroll'

describe('development INE enrollment', () => {
  let app: TestApp

  const startSession = async (identifier: string) => {
    const start = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier },
    })
    assert.equal(start.statusCode, 200)
    return JSON.parse(start.payload).tokens.accessToken as string
  }

  const enroll = (token: string) =>
    app.inject({
      method: 'POST',
      url: '/v1/identity/ine/dev-enroll',
      headers: { authorization: `Bearer ${token}` },
    })

  const voteNullifier = async (token: string) => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/identity/civic-vote-proof',
      headers: { authorization: `Bearer ${token}` },
      payload: { subjectUri, subjectType: 'cabildeo', selectedOption: 0 },
    })
    assert.equal(res.statusCode, 200, res.payload)
    return JSON.parse(res.payload).proof.voteNullifier as string
  }

  before(async () => {
    const { buildApp } = await import('../../src/index.js')
    app = await buildApp()
  })

  after(async () => {
    await app.close()
  })

  it('requires a session', async () => {
    const res = await app.inject({ method: 'POST', url: '/v1/identity/ine/dev-enroll' })
    assert.equal(res.statusCode, 401)
  })

  it('lets an enrolled session obtain a cabildeo vote proof, once', async () => {
    const token = await startSession('dev-enroll-alice.test')
    const first = await enroll(token)
    assert.equal(first.statusCode, 200, first.payload)
    assert.equal(JSON.parse(first.payload).created, true)

    const again = await enroll(token)
    assert.equal(again.statusCode, 200)
    assert.equal(JSON.parse(again.payload).created, false)

    assert.match(await voteNullifier(token), /^[a-f0-9]{64}$/)
  })

  it('makes each account its own person, and the same account the same person', async () => {
    const alice = await startSession('dev-enroll-alice.test')
    const bob = await startSession('dev-enroll-bob.test')
    for (const token of [alice, bob]) {
      assert.equal((await enroll(token)).statusCode, 200)
    }
    const aliceNullifier = await voteNullifier(alice)
    assert.notEqual(aliceNullifier, await voteNullifier(bob))

    // A second session for the same account resolves to the same person.
    const aliceAgain = await startSession('dev-enroll-alice.test')
    assert.equal((await enroll(aliceAgain)).statusCode, 200)
    assert.equal(await voteNullifier(aliceAgain), aliceNullifier)
  })
})
