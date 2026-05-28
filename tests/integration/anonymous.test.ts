import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-anon-test-'))
process.env.DATABASE_PATH = join(tmpDir, 'anon-test.db')

describe('Anonymous mode integration', () => {
  let app: TestApp
  let accessToken: string
  let did: string

  before(async () => {
    const { buildApp } = await import('../../src/index.js')
    app = await buildApp()
    const start = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'anonuser.bsky.social' },
    })
    const body = JSON.parse(start.payload)
    accessToken = body.tokens.accessToken
    did = body.attempt.did
  })

  after(async () => {
    await app.close()
  })

  it('GET /v1/sessions/me returns anonymousProfile: null when not enabled', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/sessions/me',
      headers: { authorization: `Bearer ${accessToken}` },
    })
    assert.equal(res.statusCode, 200)
    const body = JSON.parse(res.payload)
    assert.equal(body.anonymousProfile, null)
  })

  it('POST /v1/sessions/anonymous/enable creates anonymous profile', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sessions/anonymous/enable',
      headers: { authorization: `Bearer ${accessToken}`, 'accept-language': 'en' },
    })
    assert.equal(res.statusCode, 200)
    const body = JSON.parse(res.payload)
    assert.ok(body.anonymousProfile)
    assert.ok(body.anonymousProfile.id)
    assert.ok(body.anonymousProfile.displayName.startsWith('Citizen #'))
    assert.ok(body.anonymousProfile.avatarSeed)
    assert.ok(body.anonymousProfile.createdAt)
  })

  it('GET /v1/sessions/me returns anonymousProfile after enable', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/sessions/me',
      headers: { authorization: `Bearer ${accessToken}`, 'accept-language': 'en' },
    })
    assert.equal(res.statusCode, 200)
    const body = JSON.parse(res.payload)
    assert.ok(body.anonymousProfile)
    assert.ok(body.anonymousProfile.displayName.startsWith('Citizen #'))
    assert.ok(body.anonymousProfile.avatarSeed)
    assert.ok(body.anonymousProfile.createdAt)
  })

  it('POST /v1/sessions/anonymous/enable fails when already enabled', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sessions/anonymous/enable',
      headers: { authorization: `Bearer ${accessToken}`, 'accept-language': 'en' },
    })
    assert.equal(res.statusCode, 400)
    const body = JSON.parse(res.payload)
    assert.equal(body.error, 'Anonymous mode already enabled')
  })

  it('POST /v1/sessions/anonymous/disable removes anonymous profile', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sessions/anonymous/disable',
      headers: { authorization: `Bearer ${accessToken}` },
    })
    assert.equal(res.statusCode, 200)
    const body = JSON.parse(res.payload)
    assert.equal(body.disabled, true)

    const me = await app.inject({
      method: 'GET',
      url: '/v1/sessions/me',
      headers: { authorization: `Bearer ${accessToken}` },
    })
    const meBody = JSON.parse(me.payload)
    assert.equal(meBody.anonymousProfile, null)
  })

  it('manages anonymous identity cards and blocks Germ linking without device trust', async () => {
    const identities = await app.inject({
      method: 'GET',
      url: '/v1/anonymous/identities',
      headers: { authorization: `Bearer ${accessToken}` },
    })
    assert.equal(identities.statusCode, 200)
    const identitiesBody = JSON.parse(identities.payload)
    assert.equal(identitiesBody.identities.length, 1)
    const identity = identitiesBody.identities[0]
    assert.equal(identity.status, 'active')
    assert.equal(identity.deviceTrust.status, 'unknown')

    const linked = await app.inject({
      method: 'POST',
      url: '/v1/anonymous/posts',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        identityId: identity.id,
        postUri: 'at://did:plc:poster/app.bsky.feed.post/anon1',
        communityUri: 'at://did:plc:community/com.para.community.board/main',
        stats: {
          replyCount: 12,
          repostCount: 2,
          likeCount: 30,
          quoteCount: 1,
          threadCount: 4,
        },
      },
    })
    assert.equal(linked.statusCode, 201)
    const post = JSON.parse(linked.payload).post
    assert.equal(post.dmPolicy, 'off')
    assert.deepEqual(
      {
        replyCount: post.stats.replyCount,
        repostCount: post.stats.repostCount,
        likeCount: post.stats.likeCount,
        quoteCount: post.stats.quoteCount,
        threadCount: post.stats.threadCount,
      },
      { replyCount: 12, repostCount: 2, likeCount: 30, quoteCount: 1, threadCount: 4 },
    )

    const statsUpdate = await app.inject({
      method: 'PATCH',
      url: `/v1/anonymous/posts/${post.id}/stats`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        replyCount: 14,
        threadCount: 5,
      },
    })
    assert.equal(statsUpdate.statusCode, 200)
    const updatedPost = JSON.parse(statsUpdate.payload).post
    assert.equal(updatedPost.stats.replyCount, 14)
    assert.equal(updatedPost.stats.threadCount, 5)
    assert.equal(updatedPost.stats.likeCount, 30)
    assert.ok(updatedPost.stats.syncedAt)

    const blocked = await app.inject({
      method: 'POST',
      url: `/v1/anonymous/identities/${identity.id}/germ/link`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        contactUrl: 'https://landing.ger.mx/anonymous-card#opaque-burner-secret',
      },
    })
    assert.equal(blocked.statusCode, 403)
    assert.match(JSON.parse(blocked.payload).error, /Trusted device required/)

    const publicContact = await app.inject({
      method: 'GET',
      url: `/v1/anonymous/public-contact?postUri=${encodeURIComponent(post.postUri)}`,
    })
    assert.equal(publicContact.statusCode, 200)
    assert.deepEqual(JSON.parse(publicContact.payload), { dmEnabled: false })
  })

  it('links opaque Germ contact URLs after device trust and never leaks the author DID', async () => {
    const trust = await app.inject({
      method: 'POST',
      url: '/v1/device-trust/development/verify',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        platform: 'ios',
        deviceKeyId: 'test-ios-app-attest-key',
        publicKey: 'test-public-key',
      },
    })
    assert.equal(trust.statusCode, 200)
    assert.equal(JSON.parse(trust.payload).deviceTrust.status, 'trusted')

    const identities = await app.inject({
      method: 'GET',
      url: '/v1/anonymous/identities',
      headers: { authorization: `Bearer ${accessToken}` },
    })
    const identity = JSON.parse(identities.payload).identities[0]

    const rejectsDidLeak = await app.inject({
      method: 'POST',
      url: `/v1/anonymous/identities/${identity.id}/germ/link`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        contactUrl: `https://landing.ger.mx/newUser#${did}+did:plc:viewer`,
      },
    })
    assert.equal(rejectsDidLeak.statusCode, 400)
    assert.match(JSON.parse(rejectsDidLeak.payload).error, /must not include the author DID/)

    const link = await app.inject({
      method: 'POST',
      url: `/v1/anonymous/identities/${identity.id}/germ/link`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        contactUrl: 'https://landing.ger.mx/anonymous-card#opaque-burner-secret',
        providerRef: 'germ-ref-1',
        mode: 'germ-card-link',
      },
    })
    assert.equal(link.statusCode, 200)
    assert.equal(JSON.parse(link.payload).germ.provider, 'germ')

    const posts = identity.posts.length
      ? identity.posts
      : [JSON.parse((await app.inject({
        method: 'POST',
        url: '/v1/anonymous/posts',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { identityId: identity.id, postUri: 'at://did:plc:poster/app.bsky.feed.post/anon2' },
      })).payload).post]
    const enable = await app.inject({
      method: 'PATCH',
      url: `/v1/anonymous/posts/${posts[0].id}/dm-policy`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { dmPolicy: 'requests' },
    })
    assert.equal(enable.statusCode, 200)

    const publicContact = await app.inject({
      method: 'GET',
      url: `/v1/anonymous/public-contact?postUri=${encodeURIComponent(posts[0].postUri)}`,
    })
    assert.equal(publicContact.statusCode, 200)
    const contactBody = JSON.parse(publicContact.payload)
    assert.equal(contactBody.dmEnabled, true)
    assert.equal(contactBody.provider, 'germ')
    assert.equal(contactBody.contactUrl.includes(did), false)
    assert.equal(JSON.stringify(contactBody).includes(did), false)

    const gated = await app.inject({
      method: 'PATCH',
      url: `/v1/anonymous/posts/${posts[0].id}/dm-policy`,
      headers: { authorization: `Bearer ${accessToken}` },
      payload: { dmPolicy: 'para-verified' },
    })
    assert.equal(gated.statusCode, 200)
    assert.equal(JSON.parse(gated.payload).post.dmPolicy, 'para-verified')

    const publicGatedContact = await app.inject({
      method: 'GET',
      url: `/v1/anonymous/public-contact?postUri=${encodeURIComponent(posts[0].postUri)}`,
    })
    assert.equal(publicGatedContact.statusCode, 200)
    const publicGatedBody = JSON.parse(publicGatedContact.payload)
    assert.equal(publicGatedBody.dmEnabled, true)
    assert.equal(publicGatedBody.senderRequirement, 'para-verified')
    assert.equal(publicGatedBody.contactUrl, undefined)

    const unverifiedSenderStart = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'unverified-sender.bsky.social' },
    })
    const unverifiedSenderToken = JSON.parse(unverifiedSenderStart.payload).tokens.accessToken
    const unverifiedEligibility = await app.inject({
      method: 'GET',
      url: `/v1/anonymous/public-contact/eligibility?postUri=${encodeURIComponent(posts[0].postUri)}`,
      headers: { authorization: `Bearer ${unverifiedSenderToken}` },
    })
    assert.equal(unverifiedEligibility.statusCode, 403)
    assert.equal(JSON.parse(unverifiedEligibility.payload).code, 'PARA_VERIFICATION_REQUIRED')

    const verifiedSenderStart = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'verified-sender.bsky.social' },
    })
    const verifiedSenderToken = JSON.parse(verifiedSenderStart.payload).tokens.accessToken
    const grantCreate = await app.inject({
      method: 'POST',
      url: '/v1/grants',
      headers: { authorization: `Bearer ${verifiedSenderToken}` },
      payload: {
        appId: 'germ.dm',
        appName: 'Germ DM',
        appKind: 'Consumer app',
        surface: 'public',
        requestedClaims: [{ type: 'has_para_verification', disclosure: 'proof-only' }],
        proofMode: 'proof-only',
        reason: 'Allow PARA-verified anonymous DM replies',
      },
    })
    assert.equal(grantCreate.statusCode, 201)
    const senderGrant = JSON.parse(grantCreate.payload).grant
    const grantApprove = await app.inject({
      method: 'POST',
      url: `/v1/grants/${senderGrant.id}/approve`,
      headers: { authorization: `Bearer ${verifiedSenderToken}` },
      payload: { grantId: senderGrant.id, reviewNote: 'Sender verified' },
    })
    assert.equal(grantApprove.statusCode, 200)

    const verifiedEligibility = await app.inject({
      method: 'GET',
      url: `/v1/anonymous/public-contact/eligibility?postUri=${encodeURIComponent(posts[0].postUri)}`,
      headers: { authorization: `Bearer ${verifiedSenderToken}` },
    })
    assert.equal(verifiedEligibility.statusCode, 200)
    const verifiedEligibilityBody = JSON.parse(verifiedEligibility.payload)
    assert.equal(verifiedEligibilityBody.eligible, true)
    assert.equal(verifiedEligibilityBody.senderRequirement, 'para-verified')
    assert.equal(verifiedEligibilityBody.contactUrl.includes(did), false)
    assert.equal(verifiedEligibilityBody.contactUrl, contactBody.contactUrl)
  })
})
