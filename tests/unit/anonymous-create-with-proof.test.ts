import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { hexToBytes, bytesToHex } from '@noble/curves/abstract/utils'
import { signAssertion, sr25519PublicKey } from '../helpers/identitySignature.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-anon-create-proof-'))
process.env.DATABASE_PATH = join(tmpDir, 'anon-create-proof.db')

const scalarOf = (le: string): bigint =>
  BigInt('0x' + bytesToHex(hexToBytes(le).slice().reverse()))
const SCALAR = scalarOf('022411408b2871ebdfc59124c10c388e05d48acc8cb1abe6c2857d8fcd00c100')

/**
 * The additive create path (F2b / CD-10): when the client proves possession of
 * its anonymous key, the new identity row is anchored to that key and becomes
 * resolvable by key; without a proof, the legacy session path still works and
 * the row has no key. This is the first place the verifier is used end to end.
 */
describe('anonymous identity create with proof (F2b)', () => {
  let action: typeof import('../../src/services/anonymousActionProof.js')
  let anon: typeof import('../../src/services/anonymousIdentityService.js')
  let getDb: typeof import('../../src/db/connection.js').getDb
  let closeDb: typeof import('../../src/db/connection.js').closeDb

  const SESSION = 'session-create-proof'
  const pub = bytesToHex(sr25519PublicKey(SCALAR))

  const proofFor = (challenge: string) => {
    const assertion = {
      type: 'para.identity.pop.v1' as const,
      purpose: 'anon-action' as const,
      audience: action.BROKER_AUDIENCE,
      identityPub: pub,
      challenge,
      signedAt: new Date().toISOString(),
    }
    return { assertion, signature: signAssertion(SCALAR, assertion) }
  }

  before(async () => {
    ;({ getDb, closeDb } = await import('../../src/db/connection.js'))
    const { ensureSchema, runMigrations } = await import('../../src/db/migrate.js')
    ensureSchema()
    runMigrations()
    action = await import('../../src/services/anonymousActionProof.js')
    anon = await import('../../src/services/anonymousIdentityService.js')

    const now = new Date().toISOString()
    getDb()
      .prepare(`
        INSERT INTO sessions
          (session_id, did, handle, display_name, authorization_server, authenticated_at, pds_safety_json, active_persona_id, active_surface_id, created_at, updated_at, status)
        VALUES (?, ?, ?, ?, ?, ?, '{}', 'orbit', 'public', ?, ?, 'active')
      `)
      .run(SESSION, 'did:plc:createproof', 'cp.test', 'cp.test', 'https://pds.test', now, now, now)
  })

  after(() => closeDb())

  it('anchors a proven create to the identity key, resolvable by key', () => {
    const { nonce } = action.issueAnonymousActionChallenge(pub, 'create')
    const result = action.verifyAnonymousActionProof({
      signed: proofFor(nonce),
      jti: 'create-jti-1',
      action: 'create',
    })
    assert.equal(result.ok, true)
    assert.equal(result.ok && result.identityPub, pub)

    const identity = anon.createAnonymousIdentity(SESSION, {
      displayName: 'Proven',
      identityPub: result.ok ? result.identityPub : undefined,
    })

    const byKey = anon.findAnonymousIdentityRowByPub(pub)
    assert.ok(byKey, 'the proven identity is resolvable by key')
    assert.equal(byKey.id, identity.id)
    assert.equal(byKey.identity_pub, pub)
  })

  it('leaves the key null on the legacy session path (no proof)', () => {
    const identity = anon.createAnonymousIdentity(SESSION, { displayName: 'Legacy' })
    const row = getDb()
      .prepare('SELECT identity_pub FROM anonymous_identities WHERE id = ?')
      .get(identity.id) as { identity_pub: string | null }
    assert.equal(row.identity_pub, null)
  })

  it('update authorizes by key: proof for the owning key succeeds, another key is refused', () => {
    // Reuse the identity anchored to `pub` in the first test (one key ↔ one row).
    const owned = anon.findAnonymousIdentityRowByPub(pub)
    assert.ok(owned, 'expected the key-anchored identity from the first test')
    const identityId = owned.id as string

    // The owning key updates it.
    const updated = anon.updateAnonymousIdentity(SESSION, identityId, {
      displayName: 'Renamed by key',
      requireIdentityPub: pub,
    })
    assert.equal(updated.displayName, 'Renamed by key')

    // A different key is refused with a key mismatch.
    const otherPub = 'bb'.repeat(32)
    assert.throws(
      () =>
        anon.updateAnonymousIdentity(SESSION, identityId, {
          displayName: 'Hijacked',
          requireIdentityPub: otherPub,
        }),
      /KEY_MISMATCH|does not match/i,
    )
  })

  it('resolves an identity by key alone (no session in the lookup)', () => {
    const card = anon.getAnonymousIdentityByKey(SESSION, pub)
    assert.ok(card, 'the key-anchored identity resolves by key')
    // It resolved to the row anchored to `pub`.
    const byKey = anon.findAnonymousIdentityRowByPub(pub)
    assert.equal(card.id, byKey!.id)
    // An unknown key resolves to nothing.
    assert.equal(anon.getAnonymousIdentityByKey(SESSION, 'cc'.repeat(32)), null)
  })

  it('link-post authorizes by key: owning key links, wrong key is refused', () => {
    const owned = anon.findAnonymousIdentityRowByPub(pub)!
    const identityId = owned.id as string

    const linked = anon.linkAnonymousPost(SESSION, {
      identityId,
      postUri: 'at://did:plc:createproof/app.bsky.feed.post/p1',
      requireIdentityPub: pub,
    })
    assert.equal(linked.post.identityId, identityId)

    assert.throws(
      () =>
        anon.linkAnonymousPost(SESSION, {
          identityId,
          postUri: 'at://did:plc:createproof/app.bsky.feed.post/p2',
          requireIdentityPub: 'bb'.repeat(32),
        }),
      /KEY_MISMATCH|does not match/i,
    )
  })

  it('germ link/unlink authorize by key', async () => {
    const identityId = anon.findAnonymousIdentityRowByPub(pub)!.id as string
    // Germ linking requires a trusted device (anti-abuse, a 🟢 session use).
    const { upsertDevelopmentTrustedDevice } = await import(
      '../../src/services/deviceTrustService.js'
    )
    upsertDevelopmentTrustedDevice(SESSION, { platform: 'ios', deviceKeyId: 'dev-key-1' })

    const germ = anon.linkGermContact(SESSION, identityId, {
      contactUrl: 'https://germ.example/c/abc',
      requireIdentityPub: pub,
    })
    assert.equal(germ.status, 'active')

    assert.throws(
      () =>
        anon.linkGermContact(SESSION, identityId, {
          contactUrl: 'https://germ.example/c/def',
          requireIdentityPub: 'bb'.repeat(32),
        }),
      /KEY_MISMATCH|does not match/i,
    )

    // Unlink with the owning key succeeds; wrong key is refused.
    assert.throws(
      () => anon.unlinkGermContact(SESSION, identityId, 'bb'.repeat(32)),
      /KEY_MISMATCH|does not match/i,
    )
    const revoked = anon.unlinkGermContact(SESSION, identityId, pub)
    assert.equal(revoked?.status, 'revoked')
  })
})
