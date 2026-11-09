// Writes zkp/artifact-manifest.test.json for the files build-test-artifacts.sh
// produced: their sha256, and the sha256 of the circuit sources they were
// built from, so the set cannot silently drift from the circuits.
import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ZKP = join(dirname(fileURLToPath(import.meta.url)), '..')
const sha256 = (path) => createHash('sha256').update(readFileSync(join(ZKP, path))).digest('hex')

// Artifact ids and circuit ids match the production manifest, which the unit
// tests compare against. ine_age_proof's circuit id predates the _dev suffix.
const CIRCUITS = [
  { name: 'ine_age_proof', circuitId: 'ine_age_proof_v1' },
  { name: 'nullifier_proof_v2', circuitId: 'nullifier_proof_v2_dev' },
]
const artifacts = {}
const circuits = {}
for (const { name, circuitId } of CIRCUITS) {
  circuits[circuitId] = { source: `circuits/${name}.circom`, sha256: sha256(`circuits/${name}.circom`) }
  for (const [kind, file] of [['wasm', `${name}_test.wasm`], ['zkey', `${name}_test.zkey`], ['vkey', `${name}_test_vkey.json`]]) {
    const path = `test-artifacts/${file}`
    artifacts[`${name}_${kind}`] = { circuitId, kind, path, sha256: sha256(path) }
  }
}
// Included by nullifier_proof_v2 (and the v3 draft): a change to it changes the
// circuit, so it is pinned like a circuit source.
circuits.merkle_lib = { source: 'circuits/lib/merkle.circom', sha256: sha256('circuits/lib/merkle.circom') }

const manifest = {
  version: '1.0.0',
  testOnly: true,
  note: 'INSECURE test-only Groth16 keys (public setup entropy). Loaded only with ZKP_ARTIFACT_SET=test, never in production. Rebuild with zkp/scripts/build-test-artifacts.sh.',
  circuits,
  artifacts,
}
writeFileSync(join(ZKP, 'artifact-manifest.test.json'), JSON.stringify(manifest, null, 2) + '\n')
