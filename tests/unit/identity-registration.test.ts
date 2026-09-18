import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { hexToBytes, bytesToHex } from '@noble/curves/abstract/utils'
import {
  signAssertion,
  sr25519PublicKey,
} from '../helpers/identitySignature.js'
import type { IdentityAssertion } from '../../src/services/identitySignature.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-identity-registration-'))
process.env.DATABASE_PATH = join(tmpDir, 'identity-registration.db')

// Little-endian scalar hex -> bigint, matching identity-signature.test.ts.
const scalarOf = (privHexLE: string): bigint =>
  BigInt('0x' + bytesToHex(hexToBytes(privHexLE).slice().reverse()))

// Two distinct identity scalars (arbitrary but fixed, 32-byte LE hex, well
// below the group order so they are valid scalars).
// 32-byte little-endian hex; the most-significant byte (last two chars) is 00
// so the scalar is < 2^248 and safely below the group order l.
const SCALAR_A = scalarOf(
  '022411408b2871ebdfc59124c10c388e05d48acc8cb1abe6c2857d8fcd00c100',
)
const SCALAR_B = scalarOf(
  '011dcc7e971e7813cf49906695ebb73b8ae511664c0cd5ab3f82113277f90e00',
)

describe('identity registration (CD-9)', () => {
  let svc: typeof import('../../src/services/identityRegistrationService.js')
  let getDb: typeof import('../../src/db/connection.js').getDb
  let closeDb: typeof import('../../src/db/connection.js').closeDb

  before(async () => {
    ;({ getDb, closeDb } = await import('../../src/db/connection.js'))
    const { ensureSchema, runMigrations } = await import('../../src/db/migrate.js')
    ensureSchema()
    runMigrations()
    svc = await import('../../src/services/identityRegistrationService.js')
  })

  after(() => {
    closeDb()
  })

  const pubOf = (scalar: bigint) => bytesToHex(sr25519PublicKey(scalar))

  const proofFor = (
    scalar: bigint,
    challenge: string,
    overrides: Partial<IdentityAssertion> = {},
    signedAt = new Date().toISOString(),
  ) => {
    const assertion: IdentityAssertion = {
      type: 'para.identity.pop.v1',
      purpose: 'mubez-registration',
      audience: svc.REGISTRATION_AUDIENCE,
      identityPub: pubOf(scalar),
      challenge,
      signedAt,
      ...overrides,
    }
    return { assertion, signature: signAssertion(scalar, assertion) }
  }

  // The load-bearing invariant of the whole scheme: this table relates an
  // identity key to nothing. If a later migration adds a session/seed/view
  // column or any foreign key here, this test fails and names the regression.
  it('stores identity keys with no linkage column and no foreign key', () => {
    const db = getDb()
    const columns = (
      db.prepare("PRAGMA table_info('registered_identities')").all() as {
        name: string
      }[]
    ).map((c) => c.name)
    assert.deepEqual(columns, ['identity_pub', 'registered_at'])
    for (const forbidden of ['session_id', 'seed', 'view_priv', 'did', 'person_id']) {
      assert.ok(
        !columns.includes(forbidden),
        `registered_identities must not carry ${forbidden}`,
      )
    }
    const fks = db
      .prepare("PRAGMA foreign_key_list('registered_identities')")
      .all()
    assert.equal(fks.length, 0, 'registered_identities must have no foreign key')

    // The challenge table must not be keyed to a session or an identity either.
    const challengeCols = (
      db.prepare("PRAGMA table_info('identity_registration_challenges')").all() as {
        name: string
      }[]
    ).map((c) => c.name)
    assert.ok(!challengeCols.includes('session_id'))
    assert.ok(!challengeCols.includes('identity_pub'))
    assert.equal(
      db.prepare("PRAGMA foreign_key_list('identity_registration_challenges')").all()
        .length,
      0,
    )
  })

  it('registers a key from a valid proof of possession', () => {
    const challenge = svc.issueRegistrationChallenge()
    const result = svc.registerIdentity(proofFor(SCALAR_A, challenge))
    assert.deepEqual(result, { ok: true, alreadyRegistered: false })
    assert.ok(svc.isIdentityRegistered(pubOf(SCALAR_A)))
  })

  it('rejects a replayed challenge', () => {
    const challenge = svc.issueRegistrationChallenge()
    assert.equal(svc.registerIdentity(proofFor(SCALAR_B, challenge)).ok, true)
    // Same challenge again — even with a fresh valid proof — is spent.
    const replay = svc.registerIdentity(
      proofFor(SCALAR_B, challenge),
    ) as { ok: false; reason: string }
    assert.deepEqual(replay, { ok: false, reason: 'bad-challenge' })
  })

  it('re-registering a known key is an idempotent success', () => {
    const challenge = svc.issueRegistrationChallenge()
    const result = svc.registerIdentity(proofFor(SCALAR_A, challenge))
    assert.deepEqual(result, { ok: true, alreadyRegistered: true })
  })

  it('rejects an unknown challenge without touching signature work', () => {
    const result = svc.registerIdentity(
      proofFor(SCALAR_A, 'never-issued-challenge'),
    ) as { ok: false; reason: string }
    assert.deepEqual(result, { ok: false, reason: 'bad-challenge' })
  })

  it('rejects a proof for the wrong audience (cross-purpose replay)', () => {
    const challenge = svc.issueRegistrationChallenge()
    const result = svc.registerIdentity(
      proofFor(SCALAR_A, challenge, { audience: 'para-idp' }),
    ) as { ok: false; reason: string }
    assert.deepEqual(result, { ok: false, reason: 'bad-proof' })
    // A failed proof must not burn the challenge.
    assert.equal(
      svc.registerIdentity(proofFor(SCALAR_A, challenge)).ok,
      true,
    )
  })

  it('rejects a proof signed by a different key than it claims', () => {
    const challenge = svc.issueRegistrationChallenge()
    // Claim B's public key, sign with A's scalar.
    const assertion: IdentityAssertion = {
      type: 'para.identity.pop.v1',
      purpose: 'mubez-registration',
      audience: svc.REGISTRATION_AUDIENCE,
      identityPub: pubOf(SCALAR_B),
      challenge,
      signedAt: new Date().toISOString(),
    }
    const forged = { assertion, signature: signAssertion(SCALAR_A, assertion) }
    const result = svc.registerIdentity(forged) as { ok: false; reason: string }
    assert.deepEqual(result, { ok: false, reason: 'bad-proof' })
  })

  it('rejects a stale proof', () => {
    const challenge = svc.issueRegistrationChallenge()
    const old = new Date(Date.now() - 10 * 60 * 1000).toISOString()
    const result = svc.registerIdentity(
      proofFor(SCALAR_A, challenge, {}, old),
    ) as { ok: false; reason: string }
    assert.deepEqual(result, { ok: false, reason: 'bad-proof' })
  })
})
