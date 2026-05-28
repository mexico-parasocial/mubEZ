import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)
const PROJECT_ROOT = join(__dirname, '..', '..')
const ZKP_ROOT = join(PROJECT_ROOT, 'zkp')
const MANIFEST_PATH = join(ZKP_ROOT, 'artifact-manifest.json')

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
  artifacts: Record<ZkpArtifactId, ZkpArtifactManifestEntry>
}

let manifestCache: ZkpArtifactManifest | null = null

function loadManifest() {
  if (!manifestCache) {
    manifestCache = JSON.parse(readFileSync(MANIFEST_PATH, 'utf8')) as ZkpArtifactManifest
  }
  return manifestCache
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
