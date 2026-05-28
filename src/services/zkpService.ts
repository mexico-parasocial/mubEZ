import { readFileSync } from 'node:fs'
import { getVerifiedZkpArtifactPath } from './zkpArtifacts.js'

// @ts-expect-error — no ESM types available for snarkjs
import { groth16 } from 'snarkjs'
// @ts-expect-error — no ESM types available for circomlibjs
import { buildPoseidon } from 'circomlibjs'

// ─── IneAgeProof artifacts ────────────────────────────────────────────────
const AGE_WASM = () => getVerifiedZkpArtifactPath('ine_age_proof_wasm')
const AGE_ZKEY = () => getVerifiedZkpArtifactPath('ine_age_proof_zkey')
const AGE_VKEY = () => getVerifiedZkpArtifactPath('ine_age_proof_vkey')

// ─── NullifierProof artifacts ─────────────────────────────────────────────
const NULL_WASM = () => getVerifiedZkpArtifactPath('nullifier_proof_wasm')
const NULL_ZKEY = () => getVerifiedZkpArtifactPath('nullifier_proof_zkey')
const NULL_VKEY = () => getVerifiedZkpArtifactPath('nullifier_proof_vkey')

let _poseidon: Awaited<ReturnType<typeof buildPoseidon>> | null = null

async function getPoseidon() {
  if (!_poseidon) {
    _poseidon = await buildPoseidon()
  }
  return _poseidon
}

function loadVkey(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf8'))
}

/** Schema version stored with proof artifacts for circuit compatibility tracking. */
export const PROOF_SCHEMA_VERSION = '1.0.0'

/** Human-readable/stable circuit identifier. */
export const CIRCUIT_ID = 'ine_age_proof_v1'

/** BN254 field modulus. */
export const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

/**
 * Validate that a commitment (publicSignals[0]) is a non-zero element within the BN254 field.
 * The server cannot inspect the private salt; it can only reject commitments that are
 * trivially invalid (zero or >= field modulus).
 */
export function isValidCommitment(commitment: string): boolean {
  try {
    const n = BigInt(commitment)
    return n > 0n && n < FIELD_MODULUS
  } catch {
    return false
  }
}

export interface AgeProofInput {
  birthYear: number
  salt: number | string | bigint
  currentYear: number
  ageThreshold: number
}

export interface AgeProofResult {
  proof: unknown
  publicSignals: string[]
  commitment: string
}

export interface NullifierProofInput {
  birthYear: number
  salt: number | string | bigint
  communityId: number
  currentYear: number
  ageThreshold: number
}

export interface NullifierProofResult {
  proof: unknown
  publicSignals: string[]
  commitment: string
  nullifier: string
}

/**
 * Generate a ZKP proving age eligibility.
 * @deprecated For production, proofs must be generated client-side. Server-side proving is only for tests/demo.
 */
export async function generateAgeProof(input: AgeProofInput): Promise<AgeProofResult> {
  const { proof, publicSignals } = await groth16.fullProve(
    {
      birthYear: input.birthYear,
      salt: input.salt,
      currentYear: input.currentYear,
      ageThreshold: input.ageThreshold,
    },
    AGE_WASM(),
    AGE_ZKEY(),
  )

  const commitment = publicSignals[0] as string
  return { proof, publicSignals, commitment }
}

/**
 * Verify a Groth16 age proof.
 */
export async function verifyAgeProof(proof: unknown, publicSignals: string[]): Promise<boolean> {
  const vkey = loadVkey(AGE_VKEY())
  return groth16.verify(vkey, publicSignals, proof)
}

/**
 * Generate a ZKP proving age eligibility + nullifier for a community.
 * @deprecated For production, proofs must be generated client-side. Server-side proving is only for tests/demo.
 */
export async function generateNullifierProof(input: NullifierProofInput): Promise<NullifierProofResult> {
  const { proof, publicSignals } = await groth16.fullProve(
    {
      birthYear: input.birthYear,
      salt: input.salt,
      communityId: input.communityId,
      currentYear: input.currentYear,
      ageThreshold: input.ageThreshold,
    },
    NULL_WASM(),
    NULL_ZKEY(),
  )

  // publicSignals: [commitment, nullifier, communityId, currentYear, ageThreshold]
  const commitment = publicSignals[0] as string
  const nullifier = publicSignals[1] as string
  return { proof, publicSignals, commitment, nullifier }
}

/**
 * Verify a Groth16 nullifier proof.
 */
export async function verifyNullifierProof(proof: unknown, publicSignals: string[]): Promise<boolean> {
  const vkey = loadVkey(NULL_VKEY())
  return groth16.verify(vkey, publicSignals, proof)
}

/**
 * Compute the Poseidon commitment off-circuit.
 */
export async function computeCommitment(birthYear: number, salt: number | string | bigint): Promise<string> {
  const poseidon = await getPoseidon()
  const hash = poseidon([birthYear, salt])
  return poseidon.F.toString(hash)
}

/**
 * Compute the Poseidon nullifier off-circuit.
 */
export async function computeNullifier(salt: number | string | bigint, communityId: number): Promise<string> {
  const poseidon = await getPoseidon()
  const hash = poseidon([salt, communityId])
  return poseidon.F.toString(hash)
}
