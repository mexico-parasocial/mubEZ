import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, randomBytes, sign, type JsonWebKey, type KeyObject } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'
import type { CommunityAction, CommunityActionVote } from '../../src/types/index.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-communities-test-'))
process.env.DATABASE_PATH = join(tmpDir, 'communities-test.db')
process.env.RATE_LIMIT_COMMUNITY_READ_MAX = '200'
process.env.RATE_LIMIT_COMMUNITY_MUTATION_MAX = '200'
process.env.RATE_LIMIT_COMMUNITY_VOTE_MAX = '200'

type AdminFixture = {
  did: string
  keyId: string
  privateKey: KeyObject
  publicJwk: JsonWebKey
  accessToken: string
}

let app: TestApp
let closeDb: typeof import('../../src/db/connection.js').closeDb
let getDb: typeof import('../../src/db/connection.js').getDb

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(',')}]`
  const record = value as Record<string, unknown>
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(',')}}`
}

function payloadHash(payload: Record<string, unknown>) {
  return `sha256:${createHash('sha256').update(canonicalJson(payload)).digest('base64url')}`
}

function canonicalVotePayload(params: {
  action: CommunityAction
  adminDid: string
  vote: CommunityActionVote
  signedAt: string
  nonce: string
}) {
  return JSON.stringify({
    type: 'app.m8.community.vote',
    version: 1,
    communityId: params.action.communityId,
    actionId: params.action.id,
    actionType: params.action.actionType,
    payloadHash: payloadHash(params.action.payload),
    adminDid: params.adminDid,
    vote: params.vote,
    signedAt: params.signedAt,
    nonce: params.nonce,
  })
}

function createAdminFixture(name: string): Omit<AdminFixture, 'accessToken'> {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const did = `did:plc:${name}`
  return {
    did,
    keyId: `${did}#key-1`,
    privateKey,
    publicJwk: publicKey.export({ format: 'jwk' }) as JsonWebKey,
  }
}

function seedDidDoc(admin: Omit<AdminFixture, 'accessToken'>, opts?: { bareVerificationOnly?: boolean }) {
  const doc = {
    id: admin.did,
    verificationMethod: [
      {
        id: admin.keyId,
        type: 'JsonWebKey2020',
        controller: admin.did,
        publicKeyJwk: admin.publicJwk,
      },
    ],
    ...(opts?.bareVerificationOnly
      ? {}
      : {
          assertionMethod: [admin.keyId],
          authentication: [admin.keyId],
        }),
  }

  const now = new Date().toISOString()
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString()
  getDb().prepare(`
    INSERT INTO did_cache (did, doc, updated_at, expires_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(did) DO UPDATE SET doc = excluded.doc, updated_at = excluded.updated_at, expires_at = excluded.expires_at
  `).run(admin.did, JSON.stringify(doc), now, expiresAt)
}

async function startSession(identifier: string) {
  const res = await app.inject({
    method: 'POST',
    url: '/v1/sessions/start',
    payload: { identifier },
  })
  assert.equal(res.statusCode, 200)
  return JSON.parse(res.payload).tokens.accessToken as string
}

async function authed(method: string, url: string, token: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { authorization: `Bearer ${token}` },
    ...(payload === undefined ? {} : { payload }),
  })
}

function signVote(params: {
  action: CommunityAction
  admin: Pick<AdminFixture, 'did' | 'privateKey' | 'keyId'>
  vote: CommunityActionVote
  nonce?: string
  signedAt?: string
  keyId?: string
}) {
  const signedAt = params.signedAt ?? new Date().toISOString()
  const nonce = params.nonce ?? randomBytes(16).toString('base64url')
  const canonical = canonicalVotePayload({
    action: params.action,
    adminDid: params.admin.did,
    vote: params.vote,
    signedAt,
    nonce,
  })
  return {
    vote: params.vote,
    signature: sign(null, Buffer.from(canonical), params.admin.privateKey).toString('base64url'),
    signedAt,
    nonce,
    keyId: params.keyId ?? params.admin.keyId,
  }
}

async function createActiveCommunity(admins: AdminFixture[], suffix: string) {
  const create = await authed('POST', '/v1/communities', admins[0].accessToken, {
    did: `did:web:community-${suffix}.test`,
    name: `Community ${suffix}`,
    description: 'Closed beta governance test community',
  })
  assert.equal(create.statusCode, 201)
  const community = JSON.parse(create.payload).community

  const bootstrap = await authed(
    'POST',
    `/v1/communities/${community.id}/bootstrap-admins`,
    admins[0].accessToken,
    { adminDids: admins.slice(1).map((admin) => admin.did) }
  )
  assert.equal(bootstrap.statusCode, 200)
  assert.equal(JSON.parse(bootstrap.payload).community.status, 'active')

  return community
}

describe('community governance integration', () => {
  before(async () => {
    const appModule = await import('../../src/index.js')
    const dbModule = await import('../../src/db/connection.js')
    app = await appModule.buildApp()
    closeDb = dbModule.closeDb
    getDb = dbModule.getDb
  })

  after(async () => {
    await app.close()
    closeDb()
  })

  it('bootstraps admins once and executes low/high impact actions with signed votes', async () => {
    const adminSeeds = ['admin-one', 'admin-two', 'admin-three'].map(createAdminFixture)
    for (const admin of adminSeeds) seedDidDoc(admin)
    const admins: AdminFixture[] = []
    for (const admin of adminSeeds) {
      admins.push({ ...admin, accessToken: await startSession(admin.did) })
    }

    const community = await createActiveCommunity(admins, 'happy')
    const secondBootstrap = await authed(
      'POST',
      `/v1/communities/${community.id}/bootstrap-admins`,
      admins[0].accessToken,
      { adminDids: [admins[1].did] }
    )
    assert.equal(secondBootstrap.statusCode, 409)
    assert.equal(JSON.parse(secondBootstrap.payload).code, 'COMMUNITY_ALREADY_ACTIVE')

    const blogProposal = await authed('POST', `/v1/communities/${community.id}/actions`, admins[0].accessToken, {
      actionType: 'blog_post',
      payload: { title: 'Launch', content: 'Closed beta launch note' },
    })
    assert.equal(blogProposal.statusCode, 201)
    const blogAction = JSON.parse(blogProposal.payload).action as CommunityAction

    const firstBlogVote = await authed(
      'POST',
      `/v1/communities/${community.id}/actions/${blogAction.id}/vote`,
      admins[0].accessToken,
      signVote({ action: blogAction, admin: admins[0], vote: 'approve' })
    )
    assert.equal(firstBlogVote.statusCode, 202)

    const secondBlogVote = await authed(
      'POST',
      `/v1/communities/${community.id}/actions/${blogAction.id}/vote`,
      admins[1].accessToken,
      signVote({ action: blogAction, admin: admins[1], vote: 'approve' })
    )
    assert.equal(secondBlogVote.statusCode, 200)
    assert.equal(JSON.parse(secondBlogVote.payload).executed, true)

    const nameProposal = await authed('POST', `/v1/communities/${community.id}/actions`, admins[0].accessToken, {
      actionType: 'name_change',
      payload: { name: 'Renamed Community' },
    })
    assert.equal(nameProposal.statusCode, 201)
    const nameAction = JSON.parse(nameProposal.payload).action as CommunityAction

    const nameVoteOne = await authed(
      'POST',
      `/v1/communities/${community.id}/actions/${nameAction.id}/vote`,
      admins[0].accessToken,
      signVote({ action: nameAction, admin: admins[0], vote: 'approve' })
    )
    assert.equal(nameVoteOne.statusCode, 202)

    const nameVoteTwo = await authed(
      'POST',
      `/v1/communities/${community.id}/actions/${nameAction.id}/vote`,
      admins[1].accessToken,
      signVote({ action: nameAction, admin: admins[1], vote: 'approve' })
    )
    assert.equal(nameVoteTwo.statusCode, 202)
    assert.equal(JSON.parse(nameVoteTwo.payload).action.currentApprovals, 2)

    const nameVoteThree = await authed(
      'POST',
      `/v1/communities/${community.id}/actions/${nameAction.id}/vote`,
      admins[2].accessToken,
      signVote({ action: nameAction, admin: admins[2], vote: 'approve' })
    )
    assert.equal(nameVoteThree.statusCode, 200)
    assert.equal(JSON.parse(nameVoteThree.payload).executed, true)

    const updated = await authed('GET', `/v1/communities/${community.id}`, admins[0].accessToken)
    assert.equal(JSON.parse(updated.payload).community.name, 'Renamed Community')
  })

  it('rejects tampered signatures, bare verificationMethod keys, unknown key ids, duplicate votes, and non-admin voters', async () => {
    const adminSeeds = ['reject-one', 'reject-two', 'reject-three'].map(createAdminFixture)
    for (const admin of adminSeeds) seedDidDoc(admin)
    const admins: AdminFixture[] = []
    for (const admin of adminSeeds) {
      admins.push({ ...admin, accessToken: await startSession(admin.did) })
    }
    const outsiderSeed = createAdminFixture('reject-outsider')
    seedDidDoc(outsiderSeed)
    const outsider: AdminFixture = { ...outsiderSeed, accessToken: await startSession(outsiderSeed.did) }

    const community = await createActiveCommunity(admins, 'reject')
    const proposal = await authed('POST', `/v1/communities/${community.id}/actions`, admins[0].accessToken, {
      actionType: 'blog_post',
      payload: { title: 'Rejects', content: 'Signature rejection tests' },
    })
    const action = JSON.parse(proposal.payload).action as CommunityAction

    const signedApprove = signVote({ action, admin: admins[0], vote: 'approve' })
    const tamperedVote = await authed(
      'POST',
      `/v1/communities/${community.id}/actions/${action.id}/vote`,
      admins[0].accessToken,
      { ...signedApprove, vote: 'reject' }
    )
    assert.equal(tamperedVote.statusCode, 403)
    assert.equal(JSON.parse(tamperedVote.payload).code, 'INVALID_VOTE_SIGNATURE')

    const tamperedNonce = await authed(
      'POST',
      `/v1/communities/${community.id}/actions/${action.id}/vote`,
      admins[0].accessToken,
      { ...signedApprove, nonce: randomBytes(16).toString('base64url') }
    )
    assert.equal(tamperedNonce.statusCode, 403)
    assert.equal(JSON.parse(tamperedNonce.payload).code, 'INVALID_VOTE_SIGNATURE')

    const tamperedSignedAt = await authed(
      'POST',
      `/v1/communities/${community.id}/actions/${action.id}/vote`,
      admins[0].accessToken,
      { ...signedApprove, signedAt: new Date(Date.now() + 1000).toISOString() }
    )
    assert.equal(tamperedSignedAt.statusCode, 403)
    assert.equal(JSON.parse(tamperedSignedAt.payload).code, 'INVALID_VOTE_SIGNATURE')

    const unknownKey = await authed(
      'POST',
      `/v1/communities/${community.id}/actions/${action.id}/vote`,
      admins[0].accessToken,
      signVote({ action, admin: admins[0], vote: 'approve', keyId: `${admins[0].did}#missing` })
    )
    assert.equal(unknownKey.statusCode, 403)
    assert.equal(JSON.parse(unknownKey.payload).code, 'DID_KEY_NOT_FOUND')

    seedDidDoc(admins[0], { bareVerificationOnly: true })
    const bareOnly = await authed(
      'POST',
      `/v1/communities/${community.id}/actions/${action.id}/vote`,
      admins[0].accessToken,
      signVote({ action, admin: admins[0], vote: 'approve' })
    )
    assert.equal(bareOnly.statusCode, 403)
    assert.equal(JSON.parse(bareOnly.payload).code, 'DID_KEY_NOT_FOUND')
    seedDidDoc(admins[0])

    const wrongPrivateKey = await authed(
      'POST',
      `/v1/communities/${community.id}/actions/${action.id}/vote`,
      admins[0].accessToken,
      signVote({ action, admin: { ...admins[0], privateKey: admins[1].privateKey }, vote: 'approve' })
    )
    assert.equal(wrongPrivateKey.statusCode, 403)
    assert.equal(JSON.parse(wrongPrivateKey.payload).code, 'INVALID_VOTE_SIGNATURE')

    const outsiderVote = await authed(
      'POST',
      `/v1/communities/${community.id}/actions/${action.id}/vote`,
      outsider.accessToken,
      signVote({ action, admin: outsider, vote: 'approve' })
    )
    assert.equal(outsiderVote.statusCode, 403)
    assert.equal(JSON.parse(outsiderVote.payload).code, 'NOT_ADMIN')

    const validVotePayload = signVote({ action, admin: admins[0], vote: 'approve' })
    const validVote = await authed(
      'POST',
      `/v1/communities/${community.id}/actions/${action.id}/vote`,
      admins[0].accessToken,
      validVotePayload
    )
    assert.equal(validVote.statusCode, 202)

    const reusedNonce = await authed(
      'POST',
      `/v1/communities/${community.id}/actions/${action.id}/vote`,
      admins[1].accessToken,
      signVote({ action, admin: admins[1], vote: 'approve', nonce: validVotePayload.nonce })
    )
    assert.equal(reusedNonce.statusCode, 409)
    assert.equal(JSON.parse(reusedNonce.payload).code, 'SIGNATURE_NONCE_REUSED')

    const duplicateVote = await authed(
      'POST',
      `/v1/communities/${community.id}/actions/${action.id}/vote`,
      admins[0].accessToken,
      signVote({ action, admin: admins[0], vote: 'reject' })
    )
    assert.equal(duplicateVote.statusCode, 409)
    assert.equal(JSON.parse(duplicateVote.payload).code, 'ALREADY_VOTED')

    const stored = await authed('GET', `/v1/communities/${community.id}/actions/${action.id}`, admins[0].accessToken)
    assert.equal(JSON.parse(stored.payload).action.currentApprovals, 1)
  })

  it('returns DID_RESOLUTION_FAILED when an active admin DID cannot be resolved', async () => {
    const adminSeeds = ['resolve-one', 'resolve-two'].map(createAdminFixture)
    for (const admin of adminSeeds) seedDidDoc(admin)
    const unresolved = {
      did: 'did:plc:unresolvable',
      keyId: 'did:plc:unresolvable#key-1',
      ...generateKeyPairSync('ed25519'),
    }
    const admins: AdminFixture[] = []
    for (const admin of adminSeeds) {
      admins.push({ ...admin, accessToken: await startSession(admin.did) })
    }
    const unresolvedToken = await startSession(unresolved.did)

    const community = await createActiveCommunity(
      [
        admins[0],
        admins[1],
        {
          did: unresolved.did,
          keyId: unresolved.keyId,
          privateKey: unresolved.privateKey,
          publicJwk: unresolved.publicKey.export({ format: 'jwk' }) as JsonWebKey,
          accessToken: unresolvedToken,
        },
      ],
      'resolve'
    )
    const proposal = await authed('POST', `/v1/communities/${community.id}/actions`, admins[0].accessToken, {
      actionType: 'blog_post',
      payload: { title: 'Resolve', content: 'DID resolution failure test' },
    })
    const action = JSON.parse(proposal.payload).action as CommunityAction

    const vote = signVote({
      action,
      admin: {
        did: unresolved.did,
        keyId: unresolved.keyId,
        privateKey: unresolved.privateKey,
      },
      vote: 'approve',
    })
    const res = await authed(
      'POST',
      `/v1/communities/${community.id}/actions/${action.id}/vote`,
      unresolvedToken,
      vote
    )
    assert.equal(res.statusCode, 503)
    assert.equal(JSON.parse(res.payload).code, 'DID_RESOLUTION_FAILED')
  })
})
