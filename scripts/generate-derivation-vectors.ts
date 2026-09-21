import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { hexToBytes } from '@noble/curves/abstract/utils'
import { deriveVector } from '../tests/helpers/identityDerivation.js'

/*
 * Regenerates docs/identity-derivation-vectors.json from the reference
 * implementation. The seeds are fixed, arbitrary constants: vectors must stay
 * stable so iM8 can assert byte-for-byte equality across implementations.
 *
 *   pnpm exec tsx scripts/generate-derivation-vectors.ts
 */

const SEEDS = [
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0101010101010101010101010101010101010101010101010101010101010101',
  '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
]

const vectors = SEEDS.map((seed) => deriveVector(hexToBytes(seed)))

const out = {
  spec: 'docs/IDENTITY_DERIVATION.md',
  version: 1,
  curve: 'ristretto255',
  hash: 'SHA-512 (little-endian, reduced mod l)',
  vectors,
}

const path = join(dirname(fileURLToPath(import.meta.url)), '..', 'docs', 'identity-derivation-vectors.json')
writeFileSync(path, JSON.stringify(out, null, 2) + '\n')
console.log(`wrote ${path}`)
