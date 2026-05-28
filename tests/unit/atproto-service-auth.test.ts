import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createPublicKey, verify, type JsonWebKey } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-atproto-service-auth-'))
process.env.DATABASE_PATH = join(tmpDir, 'service-auth.db')

let seedDb: typeof import('../../src/db/connection.js').getDb

describe('ATProto community service auth', () => {
  let getDb: typeof import('../../src/db/connection.js').getDb
  let closeDb: typeof import('../../src/db/connection.js').closeDb
  let createCommunity: typeof import('../../src/services/communityService.js').createCommunity
  let createDidDocument: typeof import('../../src/services/community/didService.js').createDidDocument
  let createCommunityServiceAuthToken: typeof import('../../src/services/atproto/serviceAuthService.js').createCommunityServiceAuthToken
  let writeCommunityRecord: typeof import('../../src/services/community/repoSyncService.js').writeCommunityRecord

  before(async () => {
    ;({ getDb, closeDb } = await import('../../src/db/connection.js'))
    seedDb = getDb
    const migrations = await import('../../src/db/migrate.js')
    migrations.ensureSchema()
    migrations.runMigrations()
    ;({ createCommunity } = await import('../../src/services/communityService.js'))
    ;({ createDidDocument } = await import('../../src/services/community/didService.js'))
    ;({ createCommunityServiceAuthToken } = await import('../../src/services/atproto/serviceAuthService.js'))
    ;({ writeCommunityRecord } = await import('../../src/services/community/repoSyncService.js'))
  })

  after(() => {
    closeDb()
  })

  it('provisions ATProto keys and signs short-lived service auth JWTs', () => {
    seedSession('session-service-auth', 'did:plc:serviceauth')
    const community = createCommunity('session-service-auth', {
      did: 'did:web:service-auth.test',
      handle: 'service-auth.test',
      name: 'Service Auth',
      pdsHost: 'https://pds.service-auth.test',
    })

    const row = getDb().prepare('SELECT * FROM communities WHERE id = ?').get(community.id) as Record<string, unknown>
    assert.match(row.community_atproto_key_public_multibase as string, /^z/)
    assert.equal(row.community_atproto_key_type, 'secp256k1')
    assert.equal(row.community_atproto_key_id, 'did:web:service-auth.test#atproto')

    const doc = createDidDocument({
      did: row.did as string,
      handle: row.handle as string,
      pdsHost: row.pds_host as string,
      signingKeyPublic: row.signing_key_public as string,
      atprotoKeyPublicMultibase: row.community_atproto_key_public_multibase as string,
      atprotoKeyId: row.community_atproto_key_id as string,
    })
    assert.equal(doc.verificationMethod[0].id, 'did:web:service-auth.test#atproto')
    assert.equal(doc.verificationMethod[0].type, 'Multikey')
    assert.equal(doc.verificationMethod[0].publicKeyMultibase, row.community_atproto_key_public_multibase)

    const token = createCommunityServiceAuthToken(
      community.id,
      'did:web:pds.service-auth.test',
      'com.atproto.repo.createRecord',
      { now: new Date('2026-05-27T12:00:00.000Z'), ttlSeconds: 60, jti: 'fixed-jti' }
    )

    const [header, payload, signature] = token.token.split('.')
    assert.equal(JSON.parse(Buffer.from(header, 'base64url').toString()).alg, 'ES256K')
    assert.deepEqual(JSON.parse(Buffer.from(payload, 'base64url').toString()), {
      iss: 'did:web:service-auth.test',
      aud: 'did:web:pds.service-auth.test',
      iat: 1779883200,
      exp: 1779883260,
      lxm: 'com.atproto.repo.createRecord',
      jti: 'fixed-jti',
    })

    const privateJwk = JSON.parse(row.community_atproto_key_private_jwk as string) as JsonWebKey
    const publicKey = createPublicKey({
      key: { kty: privateJwk.kty, crv: privateJwk.crv, x: privateJwk.x, y: privateJwk.y },
      format: 'jwk',
    })
    assert.equal(
      verify('sha256', Buffer.from(`${header}.${payload}`), { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64url')),
      true
    )
  })

  it('uses service auth for community repo writes', async () => {
    seedSession('session-repo-sync', 'did:plc:reposync')
    const community = createCommunity('session-repo-sync', {
      did: 'did:web:repo-sync.test',
      name: 'Repo Sync',
      pdsHost: 'https://pds.repo-sync.test',
    })
    const originalFetch = globalThis.fetch
    const calls: Array<{ url: string; authorization?: string }> = []

    globalThis.fetch = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
      const url = input.toString()
      calls.push({ url, authorization: (init?.headers as Record<string, string> | undefined)?.Authorization })
      if (url.endsWith('/xrpc/com.atproto.server.describeServer')) {
        return Response.json({ did: 'did:web:pds.repo-sync.test' })
      }
      return Response.json({ uri: 'at://did:web:repo-sync.test/app.m8.community.settings/self', cid: 'bafytest' })
    }) as typeof fetch

    try {
      const result = await writeCommunityRecord(community.id, 'app.m8.community.settings', { name: 'Repo Sync' }, 'self')
      assert.equal(result.cid, 'bafytest')
      const createRecordCall = calls.find((call) => call.url.endsWith('/xrpc/com.atproto.repo.createRecord'))
      const authorization = createRecordCall?.authorization
      assert.ok(authorization?.startsWith('Bearer '))
      if (!authorization) throw new Error('Missing authorization header')
      const payload = JSON.parse(Buffer.from(authorization.split(' ')[1].split('.')[1], 'base64url').toString())
      assert.equal(payload.iss, 'did:web:repo-sync.test')
      assert.equal(payload.aud, 'did:web:pds.repo-sync.test')
      assert.equal(payload.lxm, 'com.atproto.repo.createRecord')
    } finally {
      globalThis.fetch = originalFetch
    }
  })
})

function seedSession(sessionId: string, did: string) {
  const now = new Date().toISOString()
  seedDb().prepare(`
    INSERT INTO sessions
      (session_id, did, handle, display_name, authorization_server, authenticated_at, pds_safety_json,
       active_persona_id, active_surface_id, created_at, updated_at, status)
    VALUES (?, ?, ?, ?, ?, ?, '{}', 'orbit', 'public', ?, ?, 'active')
  `).run(sessionId, did, `${did.replaceAll(':', '-')}.test`, did, 'https://pds.test', now, now, now)
}
