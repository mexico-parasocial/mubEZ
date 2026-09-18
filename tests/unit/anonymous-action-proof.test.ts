import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { hexToBytes, bytesToHex } from '@noble/curves/abstract/utils'
import { signAssertion, sr25519PublicKey } from '../helpers/identitySignature.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-anon-action-'))
process.env.DATABASE_PATH = join(tmpDir, 'anon-action.db')

const scalarOf = (le: string): bigint =>
  BigInt('0x' + bytesToHex(hexToBytes(le).slice().reverse()))
// 32-byte LE, MSB byte 00 → valid scalar below the group order.
const SCALAR = scalarOf('022411408b2871ebdfc59124c10c388e05d48acc8cb1abe6c2857d8fcd00c100')

describe('anonymous action proof (CD-10 verifier)', () => {
  let mod: typeof import('../../src/services/anonymousActionProof.js')
  let closeDb: typeof import('../../src/db/connection.js').closeDb

  const pub = bytesToHex(sr25519PublicKey(SCALAR))
  let clock = new Date('2026-09-18T12:00:00.000Z')
  const now = () => clock
  const advance = (sec: number) => {
    clock = new Date(clock.getTime() + sec * 1000)
  }

  const proofFor = (challenge: string, purpose = 'anon-action') => {
    const assertion = {
      type: 'para.identity.pop.v1' as const,
      purpose: purpose as 'anon-action',
      audience: mod.BROKER_AUDIENCE,
      identityPub: pub,
      challenge,
      signedAt: clock.toISOString(),
    }
    return { assertion, signature: signAssertion(SCALAR, assertion) }
  }

  before(async () => {
    ;({ closeDb } = await import('../../src/db/connection.js'))
    const { ensureSchema, runMigrations } = await import('../../src/db/migrate.js')
    ensureSchema()
    runMigrations()
    mod = await import('../../src/services/anonymousActionProof.js')
  })

  after(() => closeDb())

  it('verifies a valid proof and returns the identity key', () => {
    const { nonce } = mod.issueAnonymousActionChallenge(pub, 'create', now)
    const result = mod.verifyAnonymousActionProof(
      { signed: proofFor(nonce), jti: 'j-1', action: 'create' },
      now,
    )
    assert.deepEqual(result, { ok: true, identityPub: pub })
  })

  it('rejects a replay of the same proof (challenge spent)', () => {
    const { nonce } = mod.issueAnonymousActionChallenge(pub, 'update:x', now)
    const signed = proofFor(nonce)
    assert.equal(mod.verifyAnonymousActionProof({ signed, jti: 'j-2', action: 'update:x' }, now).ok, true)
    const replay = mod.verifyAnonymousActionProof({ signed, jti: 'j-2b', action: 'update:x' }, now)
    assert.deepEqual(replay, { ok: false, reason: 'bad-challenge' })
  })

  it('rejects a proof used for a different action than its challenge (binding mismatch)', () => {
    const { nonce } = mod.issueAnonymousActionChallenge(pub, 'create', now)
    // Signed over the real nonce, but submitted as a different action.
    const result = mod.verifyAnonymousActionProof(
      { signed: proofFor(nonce), jti: 'j-3', action: 'link-post:at://x' },
      now,
    )
    assert.deepEqual(result, { ok: false, reason: 'bad-challenge' })
  })

  it('rejects a proof with the wrong purpose (cross-purpose replay)', () => {
    const { nonce } = mod.issueAnonymousActionChallenge(pub, 'create', now)
    const result = mod.verifyAnonymousActionProof(
      { signed: proofFor(nonce, 'mubez-registration'), jti: 'j-4', action: 'create' },
      now,
    )
    assert.deepEqual(result, { ok: false, reason: 'bad-proof' })
  })

  it('does not consume the challenge when the proof is bad', () => {
    const { nonce } = mod.issueAnonymousActionChallenge(pub, 'create', now)
    // A tampered signature: flip the last hex char of a good signature.
    const good = proofFor(nonce)
    const badSig =
      good.signature.slice(0, -1) + (good.signature.slice(-1) === '0' ? '1' : '0')
    const bad = mod.verifyAnonymousActionProof(
      { signed: { ...good, signature: badSig }, jti: 'j-5', action: 'create' },
      now,
    )
    assert.deepEqual(bad, { ok: false, reason: 'bad-proof' })
    // The challenge survived; a good proof over it still works.
    const ok = mod.verifyAnonymousActionProof(
      { signed: proofFor(nonce), jti: 'j-5b', action: 'create' },
      now,
    )
    assert.deepEqual(ok, { ok: true, identityPub: pub })
  })

  it('rejects a proof after the challenge expires', () => {
    const { nonce } = mod.issueAnonymousActionChallenge(pub, 'create', now)
    advance(120)
    const result = mod.verifyAnonymousActionProof(
      { signed: proofFor(nonce), jti: 'j-6', action: 'create' },
      now,
    )
    // Freshness fails at the signature layer (bad-proof) or the store (bad-challenge);
    // either way it is refused.
    assert.equal(result.ok, false)
  })
})
