import { describe, it, after, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

const ARTIFACT_IDS = [
  'ine_age_proof_wasm', 'ine_age_proof_zkey', 'ine_age_proof_vkey',
  'nullifier_proof_wasm', 'nullifier_proof_zkey', 'nullifier_proof_vkey',
] as const

const zkpFile = (path: string) => new URL(`../../zkp/${path}`, import.meta.url)

describe('ZKP artifact integrity', () => {
  const saved = { set: process.env.ZKP_ARTIFACT_SET, nodeEnv: process.env.NODE_ENV }
  // snarkjs keeps a bn128 worker pool alive; release it so the run can exit.
  after(async () => {
    await (globalThis as { curve_bn128?: { terminate(): Promise<void> } | null }).curve_bn128?.terminate()
  })
  afterEach(() => {
    process.env.ZKP_ARTIFACT_SET = saved.set
    if (saved.set === undefined) delete process.env.ZKP_ARTIFACT_SET
    process.env.NODE_ENV = saved.nodeEnv
    if (saved.nodeEnv === undefined) delete process.env.NODE_ENV
  })

  it('verifies pinned artifacts before use', async () => {
    delete process.env.ZKP_ARTIFACT_SET
    const {
      getZkpArtifact,
      getZkpArtifactDigestHeader,
      readVerifiedZkpArtifact,
      verifyZkpArtifactBytes,
    } = await import('../../src/services/zkpArtifacts.js')

    const artifact = getZkpArtifact('ine_age_proof_vkey')
    const bytes = readVerifiedZkpArtifact('ine_age_proof_vkey')
    const digest = Buffer.from(artifact.sha256, 'hex').toString('base64')

    assert.ok(bytes.length > 0)
    assert.equal(getZkpArtifactDigestHeader('ine_age_proof_vkey'), `sha-256=${digest}`)
    assert.throws(
      () => verifyZkpArtifactBytes('ine_age_proof_vkey', Buffer.from('tampered')),
      /ZKP artifact integrity check failed/
    )
  })

  it('loads the production set unless the test set is asked for', async () => {
    const { activeZkpArtifactSet, getZkpArtifact } = await import('../../src/services/zkpArtifacts.js')
    for (const value of [undefined, '', 'production']) {
      if (value === undefined) delete process.env.ZKP_ARTIFACT_SET
      else process.env.ZKP_ARTIFACT_SET = value
      assert.equal(activeZkpArtifactSet(), 'production')
      assert.equal(getZkpArtifact('ine_age_proof_zkey').path, 'out/ine_age_proof_final.zkey')
    }
    process.env.ZKP_ARTIFACT_SET = 'test'
    process.env.NODE_ENV = 'test'
    assert.equal(activeZkpArtifactSet(), 'test')
    assert.equal(getZkpArtifact('ine_age_proof_zkey').path, 'test-artifacts/ine_age_proof_test.zkey')
  })

  it('refuses the forgeable test set in production, and unknown sets anywhere', async () => {
    const { activeZkpArtifactSet, getZkpArtifact } = await import('../../src/services/zkpArtifacts.js')
    process.env.ZKP_ARTIFACT_SET = 'test'
    process.env.NODE_ENV = 'production'
    assert.throws(() => activeZkpArtifactSet(), /refused in production/)
    assert.throws(() => getZkpArtifact('ine_age_proof_vkey'), /refused in production/)
    process.env.NODE_ENV = 'test'
    process.env.ZKP_ARTIFACT_SET = 'staging'
    assert.throws(() => activeZkpArtifactSet(), /must be "production" or "test"/)
  })

  it('keeps the production pins out of reach of the test set', async () => {
    const { loadZkpArtifactManifest } = await import('../../src/services/zkpArtifacts.js')
    const production = loadZkpArtifactManifest('production')
    const test = loadZkpArtifactManifest('test')
    assert.equal(production.testOnly, undefined)
    assert.equal(test.testOnly, true)
    for (const id of ARTIFACT_IDS) {
      assert.ok(production.artifacts[id].path.startsWith('out/'), id)
      assert.ok(test.artifacts[id].path.startsWith('test-artifacts/'), id)
      assert.notEqual(test.artifacts[id].sha256, production.artifacts[id].sha256, id)
      assert.equal(test.artifacts[id].circuitId, production.artifacts[id].circuitId, id)
    }
  })

  it('pins every test artifact, and the circuit sources they were built from', async () => {
    const { loadZkpArtifactManifest, verifyZkpArtifactBytes } = await import('../../src/services/zkpArtifacts.js')
    const test = loadZkpArtifactManifest('test')
    for (const id of ARTIFACT_IDS) {
      const entry = test.artifacts[id]
      verifyZkpArtifactBytes(id, readFileSync(zkpFile(entry.path)), entry.sha256)
    }
    // A changed circuit without rebuilt keys fails here, not deep in a proof.
    for (const [circuitId, circuit] of Object.entries(test.circuits ?? {})) {
      const actual = createHash('sha256').update(readFileSync(zkpFile(circuit.source))).digest('hex')
      assert.equal(actual, circuit.sha256, `${circuitId}: ${circuit.source} changed; run pnpm zkp:test-artifacts`)
    }
    assert.deepEqual(Object.keys(test.circuits ?? {}).sort(), ['ine_age_proof_v1', 'nullifier_proof_v1'])
  })

  it('proves and verifies with the test set, and the production key rejects those proofs', async () => {
    process.env.ZKP_ARTIFACT_SET = 'test'
    process.env.NODE_ENV = 'test'
    const { generateAgeProof, verifyAgeProof, computeCommitment } = await import('../../src/services/zkpService.js')
    const proof = await generateAgeProof({ birthYear: 1990, salt: 123456789n, currentYear: 2026, ageThreshold: 18 })
    assert.equal(proof.commitment, await computeCommitment(1990, 123456789n))
    assert.equal(await verifyAgeProof(proof.proof, proof.publicSignals), true)
    assert.equal(await verifyAgeProof(proof.proof, [proof.publicSignals[0], '2026', '17']), false)

    // A test-key proof is not a production proof.
    process.env.ZKP_ARTIFACT_SET = 'production'
    assert.equal(await verifyAgeProof(proof.proof, proof.publicSignals), false)
  })
})
