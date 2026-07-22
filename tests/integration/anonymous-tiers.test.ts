import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-anon-tiers-test-'))
process.env.DATABASE_PATH = join(tmpDir, 'anon-tiers-test.db')

describe('anonymous identity tiers (main voice vs burner voices)', () => {
  let app: TestApp
  let tokenA: string
  let tokenB: string
  let profileA: { id: string }

  before(async () => {
    const { buildApp } = await import('../../src/index.js')
    app = await buildApp()

    for (const [name, assign] of [
      ['voice-a.bsky.social', (t: string) => (tokenA = t)],
      ['voice-b.bsky.social', (t: string) => (tokenB = t)],
    ] as const) {
      const start = await app.inject({
        method: 'POST',
        url: '/v1/sessions/start',
        payload: { identifier: name },
      })
      assign(JSON.parse(start.payload).tokens.accessToken)
    }

    // Both users enable their default anonymous identity ("main voice").
    for (const token of [tokenA, tokenB]) {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/sessions/anonymous/enable',
        headers: { authorization: `Bearer ${token}` },
      })
      assert.equal(res.statusCode, 200)
      if (token === tokenA) profileA = JSON.parse(res.payload).anonymousProfile
    }
  })

  after(async () => {
    await app.close()
  })

  it('follows and unfollows a default anonymous profile', async () => {
    const follow = await app.inject({
      method: 'POST',
      url: `/v1/anonymous/profiles/${profileA.id}/follow`,
      headers: { authorization: `Bearer ${tokenB}` },
    })
    assert.equal(follow.statusCode, 200)
    assert.equal(JSON.parse(follow.payload).following, true)
    assert.equal(JSON.parse(follow.payload).followerCount, 1)

    const read = await app.inject({
      method: 'GET',
      url: `/v1/anonymous/profiles/${profileA.id}`,
      headers: { authorization: `Bearer ${tokenB}` },
    })
    assert.equal(JSON.parse(read.payload).following, true)
    assert.equal(JSON.parse(read.payload).followerCount, 1)

    const unfollow = await app.inject({
      method: 'DELETE',
      url: `/v1/anonymous/profiles/${profileA.id}/follow`,
      headers: { authorization: `Bearer ${tokenB}` },
    })
    assert.equal(unfollow.statusCode, 200)
    assert.equal(JSON.parse(unfollow.payload).following, false)
    assert.equal(JSON.parse(unfollow.payload).followerCount, 0)
  })

  it('rejects following isolated burner identities by design', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/v1/anonymous/identities',
      headers: { authorization: `Bearer ${tokenA}` },
      payload: { displayName: 'Burner Voice' },
    })
    assert.equal(created.statusCode, 201)
    const burner = JSON.parse(created.payload).identity

    const follow = await app.inject({
      method: 'POST',
      url: `/v1/anonymous/profiles/${burner.id}/follow`,
      headers: { authorization: `Bearer ${tokenB}` },
    })
    assert.equal(follow.statusCode, 403)
    assert.equal(JSON.parse(follow.payload).code, 'ISOLATED_NOT_FOLLOWABLE')
  })

  it('follows the folded default identity via its identity id', async () => {
    const identities = await app.inject({
      method: 'GET',
      url: '/v1/anonymous/identities',
      headers: { authorization: `Bearer ${tokenA}` },
    })
    const cards = JSON.parse(identities.payload).identities
    const folded = cards.find(
      (i: { id: string }) => i.id === `anon-identity-${profileA.id}`,
    )
    assert.ok(folded)
    // Server-assigned tiers: folded default = main voice, created = burner.
    assert.equal(folded.tier, 'main')
    assert.ok(cards.every((i: { tier: string }) => i.tier === 'main' || i.tier === 'burner'))
    assert.ok(cards.some((i: { tier: string }) => i.tier === 'burner'))

    const follow = await app.inject({
      method: 'POST',
      url: `/v1/anonymous/profiles/${folded.id}/follow`,
      headers: { authorization: `Bearer ${tokenB}` },
    })
    assert.equal(follow.statusCode, 200)
    assert.equal(JSON.parse(follow.payload).following, true)
  })

  it('rejects self-follow and followers without their own anon profile', async () => {
    const self = await app.inject({
      method: 'POST',
      url: `/v1/anonymous/profiles/${profileA.id}/follow`,
      headers: { authorization: `Bearer ${tokenA}` },
    })
    assert.equal(self.statusCode, 400)
    assert.equal(JSON.parse(self.payload).code, 'CANNOT_FOLLOW_SELF')

    const start = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'no-profile.bsky.social' },
    })
    const bareToken = JSON.parse(start.payload).tokens.accessToken
    const res = await app.inject({
      method: 'POST',
      url: `/v1/anonymous/profiles/${profileA.id}/follow`,
      headers: { authorization: `Bearer ${bareToken}` },
    })
    assert.equal(res.statusCode, 400)
    assert.equal(JSON.parse(res.payload).code, 'ANON_PROFILE_REQUIRED')
  })

  it('burns and rotates a burner identity after each post', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/v1/anonymous/identities',
      headers: { authorization: `Bearer ${tokenA}` },
      payload: { displayName: 'One-Post Voice', burnAfter: 'post' },
    })
    assert.equal(created.statusCode, 201)
    const burner = JSON.parse(created.payload).identity
    assert.equal(burner.burnAfter, 'post')

    const first = await app.inject({
      method: 'POST',
      url: '/v1/anonymous/posts',
      headers: { authorization: `Bearer ${tokenA}` },
      payload: {
        identityId: burner.id,
        postUri: 'at://did:plc:example/app.bsky.feed.post/burn-1',
      },
    })
    assert.equal(first.statusCode, 201)
    const firstBody = JSON.parse(first.payload)
    assert.ok(firstBody.rotatedIdentity)
    assert.equal(firstBody.rotatedIdentity.burnAfter, 'post')
    assert.notEqual(firstBody.rotatedIdentity.id, burner.id)

    // The old burner is archived and refuses new posts.
    const archived = await app.inject({
      method: 'POST',
      url: '/v1/anonymous/posts',
      headers: { authorization: `Bearer ${tokenA}` },
      payload: {
        identityId: burner.id,
        postUri: 'at://did:plc:example/app.bsky.feed.post/burn-2',
      },
    })
    assert.equal(archived.statusCode, 409)

    // The replacement burner speaks and rotates again.
    const second = await app.inject({
      method: 'POST',
      url: '/v1/anonymous/posts',
      headers: { authorization: `Bearer ${tokenA}` },
      payload: {
        identityId: firstBody.rotatedIdentity.id,
        postUri: 'at://did:plc:example/app.bsky.feed.post/burn-3',
      },
    })
    assert.equal(second.statusCode, 201)
    assert.ok(JSON.parse(second.payload).rotatedIdentity)
  })
})
