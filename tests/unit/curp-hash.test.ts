import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import {
  computeCurpHash,
  computeDistrictHash,
  verifyCurpHash,
  isLegacyIdentifierHash,
  setPepperProvider,
  type PepperProvider,
  type PepperSecret,
} from '../../src/services/curpHash.js'

class StaticPepperProvider implements PepperProvider {
  constructor(private readonly peppers: PepperSecret[]) {}

  async getActivePepper(): Promise<PepperSecret> {
    return this.peppers[0]
  }

  async getPepperByKeyId(keyId: string): Promise<PepperSecret | null> {
    return this.peppers.find((p) => p.keyId === keyId) ?? null
  }
}

const pepperA: PepperSecret = {
  keyId: 'test-pepper-a',
  secret: Buffer.from('a'.repeat(32), 'utf8'),
}
const pepperB: PepperSecret = {
  keyId: 'test-pepper-b',
  secret: Buffer.from('b'.repeat(32), 'utf8'),
}

const provider = new StaticPepperProvider([pepperA])

const CURP = 'GARC900101HJCRRL09'

describe('curpHash service', () => {
  before(() => setPepperProvider(provider))
  after(() => setPepperProvider(null))

  it('produces a self-describing, deterministic peppered hash', async () => {
    const hash = await computeCurpHash(CURP)
    assert.match(hash, /^hmac-sha256:test-pepper-a:[0-9a-f]{64}$/)
    assert.equal(await computeCurpHash(CURP), hash)
    assert.equal(isLegacyIdentifierHash(hash), false)
  })

  it('normalizes CURP case and whitespace before hashing', async () => {
    const canonical = await computeCurpHash(CURP)
    assert.equal(await computeCurpHash(`  ${CURP.toLowerCase()} `), canonical)
  })

  it('domain-separates curp and district hashes', async () => {
    const curpHash = await computeCurpHash('X')
    const districtHash = await computeDistrictHash('X', '')
    assert.notEqual(curpHash.split(':')[2], districtHash.split(':')[2])
  })

  it('verifies a peppered hash and reports non-legacy', async () => {
    const hash = await computeCurpHash(CURP)
    assert.deepEqual(await verifyCurpHash(CURP, hash), { matches: true, legacy: false })
    assert.deepEqual(await verifyCurpHash('OTRO900101HJCRRL08', hash), {
      matches: false,
      reason: 'mismatch',
    })
  })

  it('verifies hashes made under a previous pepper after rotation', async () => {
    const oldHash = await computeCurpHash(CURP, new StaticPepperProvider([pepperB]))
    const rotated = new StaticPepperProvider([pepperA, pepperB])
    assert.deepEqual(await verifyCurpHash(CURP, oldHash, rotated), {
      matches: true,
      legacy: false,
    })
  })

  it('rejects hashes whose pepper is unknown or retired', async () => {
    const foreign = await computeCurpHash(CURP, new StaticPepperProvider([pepperB]))
    const result = await verifyCurpHash(CURP, foreign)
    assert.deepEqual(result, { matches: false, reason: 'unknown_key_id' })
  })

  it('recognizes and matches legacy truncated sha256 hashes, flagging them for re-issuance', async () => {
    const legacy = `sha256:${createHash('sha256').update(CURP).digest('hex').slice(0, 16)}`
    assert.equal(isLegacyIdentifierHash(legacy), true)
    assert.deepEqual(await verifyCurpHash(CURP, legacy), { matches: true, legacy: true })
    assert.deepEqual(await verifyCurpHash('OTRO900101HJCRRL08', legacy), {
      matches: false,
      reason: 'mismatch',
    })
  })

  it('rejects unrecognized formats instead of guessing', async () => {
    assert.deepEqual(await verifyCurpHash(CURP, 'md5:whatever'), {
      matches: false,
      reason: 'unrecognized_format',
    })
  })

  /*
   * Brute-force regression: the legacy scheme let an attacker with the stored
   * hashes enumerate candidate CURPs offline and match them with plain sha256.
   * With the pepper, enumerating candidates without the pepper must find
   * nothing, even when the true CURP is in the candidate set.
   */
  it('resists offline enumeration without the pepper', async () => {
    const stored = await computeCurpHash(CURP)
    const storedDigest = stored.split(':')[2]

    const candidates = [CURP, 'OTRO900101HJCRRL08', 'PEMJ850505MDFRRN01']
    for (const candidate of candidates) {
      const unsaltedFull = createHash('sha256').update(candidate).digest('hex')
      assert.notEqual(unsaltedFull, storedDigest)
      const wrongPepper = await computeCurpHash(candidate, new StaticPepperProvider([pepperB]))
      assert.notEqual(wrongPepper.split(':')[2], storedDigest)
    }

    // The same enumeration DOES break the legacy format - that asymmetry is
    // the point of this migration. If this assertion ever fails, the legacy
    // path has silently changed and this test must be rethought.
    const legacyStored = `sha256:${createHash('sha256').update(CURP).digest('hex').slice(0, 16)}`
    const bruteForced = candidates.find(
      (c) => `sha256:${createHash('sha256').update(c).digest('hex').slice(0, 16)}` === legacyStored,
    )
    assert.equal(bruteForced, CURP)
  })
})
