import { secretFromSeed, getPublicKey, sign } from '@scure/sr25519'
import { hexToBytes, bytesToHex } from '@noble/curves/abstract/utils'
import { utf8ToBytes } from '@noble/hashes/utils'

/**
 * sr25519 attestation of proof artifacts, per the `para.artifact.v1` contract.
 *
 * The canonical encoding below MUST stay byte-identical to
 * `encodeArtifact()` in `iM8/src/services/artifactVerification.ts` — the
 * client verifies with that encoding; the cross-repo vector in
 * `docs/artifact-attestation-vectors.json` pins both sides to it.
 *
 * Signing key: 32-byte hex seed in `M8_ARTIFACT_ISSUER_SEED`. Unset means the
 * broker stays in its honest `unsigned` state — artifacts go out without an
 * attestation and the client shows them as unverifiable, exactly as before.
 * The corresponding public key (32-byte hex) is what clients pin in
 * `EXPO_PUBLIC_M8_TRUSTED_ISSUERS`; it is exposed for convenience by
 * `artifactIssuerPublicKey()` and published in the vectors file.
 */

const SEED_ENV = 'M8_ARTIFACT_ISSUER_SEED'
const HEX32 = /^[0-9a-fA-F]{64}$/

/** Row shape as stored in proof_artifacts (snake_case columns). */
export interface ArtifactRow {
  id: string
  grant_id: string
  request_id: string
  claim_type: string
  requested_value: string | null
  outcome: string
  statement: string
  proof_mode: string
  issuer_id: string
  verifier_id: string
  audience_app_id: string
  surface: string
  issued_at: string
  expires_at: string | null
}

export function encodeArtifactRow(row: ArtifactRow): Uint8Array {
  return utf8ToBytes(
    [
      'para.artifact.v1',
      row.id,
      row.grant_id,
      row.request_id,
      row.claim_type,
      row.requested_value ?? '',
      row.outcome,
      row.statement,
      row.proof_mode,
      row.issuer_id,
      row.verifier_id,
      row.audience_app_id,
      row.surface,
      row.issued_at,
      row.expires_at ?? '',
    ].join('\n'),
  )
}

let cached: { secret: Uint8Array; publicKey: string } | null | undefined

function loadKey(): { secret: Uint8Array; publicKey: string } | null {
  if (cached !== undefined) return cached
  const seed = process.env[SEED_ENV]
  if (!seed || !HEX32.test(seed)) {
    cached = null
    return null
  }
  const secret = secretFromSeed(hexToBytes(seed))
  cached = { secret, publicKey: bytesToHex(getPublicKey(secret)) }
  return cached
}

/** The issuer public key (32-byte hex), or null when signing is disabled. */
export function artifactIssuerPublicKey(): string | null {
  return loadKey()?.publicKey ?? null
}

export interface ArtifactAttestation {
  alg: 'para.artifact.v1'
  issuerPub: string
  /** 64-byte sr25519 signature over the canonical encoding, hex. */
  signature: string
}

/**
 * Sign one artifact row AT ISSUANCE and store the result. Returns null when
 * no seed is configured — callers omit the attestation entirely rather than
 * sending an empty one, so the client's `unsigned` state keeps meaning
 * exactly "no attestation attached".
 *
 * Signatures are randomized (fresh nonce entropy per signature, standard
 * Schnorrkel) — two signatures over the same row differ. That is why the
 * attestation is signed once when the artifact is created and stored in
 * `attestation_json`, never re-derived on read: a stored proof artifact is
 * evidence, and evidence must not silently change bytes between fetches.
 */
export function signArtifactRow(row: ArtifactRow): ArtifactAttestation | null {
  const key = loadKey()
  if (!key) return null
  const signature = sign(key.secret, encodeArtifactRow(row))
  return {
    alg: 'para.artifact.v1',
    issuerPub: key.publicKey,
    signature: bytesToHex(signature),
  }
}

/**
 * Exposed for tests and vector generation with an explicit seed. `randomHex`
 * fixes the nonce entropy so published vectors are reproducible byte-for-byte;
 * production signing leaves it unset (fresh entropy per signature).
 */
export function signWithSeed(
  seedHex: string,
  row: ArtifactRow,
  randomHex?: string,
): { attestation: ArtifactAttestation; publicKey: string; canonical: string } {
  if (!HEX32.test(seedHex)) throw new Error('seed must be 32-byte hex')
  const secret = secretFromSeed(hexToBytes(seedHex))
  const publicKey = bytesToHex(getPublicKey(secret))
  const encoded = encodeArtifactRow(row)
  const signature = randomHex
    ? sign(secret, encoded, hexToBytes(randomHex))
    : sign(secret, encoded)
  return {
    attestation: {
      alg: 'para.artifact.v1',
      issuerPub: publicKey,
      signature: bytesToHex(signature),
    },
    publicKey,
    canonical: new TextDecoder().decode(encoded),
  }
}
