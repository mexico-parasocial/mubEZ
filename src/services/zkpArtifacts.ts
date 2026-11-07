import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)
const PROJECT_ROOT = join(__dirname, '..', '..')
const ZKP_ROOT = join(PROJECT_ROOT, 'zkp')

/*
 * Two pinned artifact sets for the same circuits:
 *
 * - "production" (artifact-manifest.json): the real Groth16 keys. The wasm
 *   and zkey are not in git and must be provisioned next to the vkeys.
 * - "test" (artifact-manifest.test.json): keys built by
 *   zkp/scripts/build-test-artifacts.sh with public entropy, committed so
 *   tests can prove. Anyone can forge proofs against them, so they load only
 *   with ZKP_ARTIFACT_SET=test, which is refused when NODE_ENV=production
 *   (here and at boot, in start/env.ts), and they are kept out of the build
 *   and the image.
 *
 * Read from process.env rather than the Adonis env service, so scripts and
 * unit tests that never boot the app pick the same set.
 */
export type ZkpArtifactSet = 'production' | 'test'

const MANIFEST_PATHS: Record<ZkpArtifactSet, string> = {
  production: join(ZKP_ROOT, 'artifact-manifest.json'),
  test: join(ZKP_ROOT, 'artifact-manifest.test.json'),
}

export function activeZkpArtifactSet(): ZkpArtifactSet {
  const set = process.env.ZKP_ARTIFACT_SET
  if (set === undefined || set === '' || set === 'production') return 'production'
  if (set !== 'test') {
    throw new Error(`ZKP_ARTIFACT_SET must be "production" or "test", got "${set}"`)
  }
  if (process.env.NODE_ENV === 'production') {
    throw new Error('ZKP_ARTIFACT_SET=test is refused in production: its proving keys are forgeable')
  }
  return 'test'
}

export type ZkpArtifactId =
  | 'ine_age_proof_wasm'
  | 'ine_age_proof_zkey'
  | 'ine_age_proof_vkey'
  | 'nullifier_proof_wasm'
  | 'nullifier_proof_zkey'
  | 'nullifier_proof_vkey'

export type ZkpArtifactManifestEntry = {
  circuitId: string
  kind: 'wasm' | 'zkey' | 'vkey'
  path: string
  sha256: string
}

type ZkpArtifactManifest = {
  version: string
  /** Set only in the test manifest; a production load refuses it. */
  testOnly?: boolean
  /** Test manifest: the circuit sources the set was built from. */
  circuits?: Record<string, { source: string; sha256: string }>
  artifacts: Record<ZkpArtifactId, ZkpArtifactManifestEntry>
}

const manifestCache = new Map<ZkpArtifactSet, ZkpArtifactManifest>()

export function loadZkpArtifactManifest(set: ZkpArtifactSet = activeZkpArtifactSet()): ZkpArtifactManifest {
  let manifest = manifestCache.get(set)
  if (!manifest) {
    manifest = JSON.parse(readFileSync(MANIFEST_PATHS[set], 'utf8')) as ZkpArtifactManifest
    // The flag and the file must agree, so a misplaced file cannot swap sets.
    if ((manifest.testOnly === true) !== (set === 'test')) {
      throw new Error(`ZKP artifact manifest for the ${set} set has testOnly=${manifest.testOnly === true}`)
    }
    manifestCache.set(set, manifest)
  }
  return manifest
}

function loadManifest() {
  return loadZkpArtifactManifest()
}

export function sha256Hex(bytes: Buffer | string) {
  return createHash('sha256').update(bytes).digest('hex')
}

export function verifyZkpArtifactBytes(
  artifactId: ZkpArtifactId,
  bytes: Buffer | string,
  expectedSha256 = getZkpArtifact(artifactId).sha256,
) {
  const actual = sha256Hex(bytes)
  if (actual !== expectedSha256) {
    throw new Error(`ZKP artifact integrity check failed for ${artifactId}: expected ${expectedSha256}, got ${actual}`)
  }
}

export function getZkpArtifact(artifactId: ZkpArtifactId): ZkpArtifactManifestEntry {
  const artifact = loadManifest().artifacts[artifactId]
  if (!artifact) {
    throw new Error(`Unknown ZKP artifact: ${artifactId}`)
  }
  return artifact
}

export function getVerifiedZkpArtifactPath(artifactId: ZkpArtifactId): string {
  const artifact = getZkpArtifact(artifactId)
  const path = join(ZKP_ROOT, artifact.path)
  verifyZkpArtifactBytes(artifactId, readFileSync(path), artifact.sha256)
  return path
}

export function readVerifiedZkpArtifact(artifactId: ZkpArtifactId): Buffer {
  const path = getVerifiedZkpArtifactPath(artifactId)
  const bytes = readFileSync(path)
  verifyZkpArtifactBytes(artifactId, bytes)
  return bytes
}

export function getZkpArtifactDigestHeader(artifactId: ZkpArtifactId) {
  const digest = Buffer.from(getZkpArtifact(artifactId).sha256, 'hex').toString('base64')
  return `sha-256=${digest}`
}
