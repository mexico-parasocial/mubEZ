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
})
