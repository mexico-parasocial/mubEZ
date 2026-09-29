#!/usr/bin/env node
/*
 * Constraint checks for the v3 draft circuit (docs/V3_CIRCUIT_SPEC.md).
 *
 * Compiles AgePresentationV3 at depth 4 into a temp directory, then computes
 * witnesses: valid inputs must satisfy every constraint, and each invalid
 * case must fail. No trusted setup is involved. Requires `circom` on PATH.
 *
 *   node zkp/scripts/check-age-presentation-v3.mjs
 */
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { buildPoseidon } from 'circomlibjs'
import * as snarkjs from 'snarkjs'

const DEPTH = 4
const here = dirname(fileURLToPath(import.meta.url))
const zkpRoot = join(here, '..')
const work = mkdtempSync(join(tmpdir(), 'age-v3-'))

const source = readFileSync(join(zkpRoot, 'circuits', 'age_presentation_v3.circom'), 'utf8')
  .replace('AgePresentationV3(20);', `AgePresentationV3(${DEPTH});`)
  .replaceAll('"../circomlib/', `"${join(zkpRoot, 'circomlib')}/`)
  .replace('"./lib/merkle.circom"', `"${join(zkpRoot, 'circuits', 'lib', 'merkle.circom')}"`)
writeFileSync(join(work, 'age_v3.circom'), source)
execFileSync('circom', [join(work, 'age_v3.circom'), '--O2', '--r1cs', '--wasm', '-o', work], { stdio: 'pipe' })
const wasm = join(work, 'age_v3_js', 'age_v3.wasm')
const r1cs = join(work, 'age_v3.r1cs')

const p = await buildPoseidon()
const H = (...xs) => p.F.toObject(p(xs.map(BigInt)))

const LEAF_TAG = 1n
const NYM_TAG = 2n
const dayOf = (iso) => Math.floor((Date.parse(iso) - Date.parse('1900-01-01T00:00:00Z')) / 86_400_000)

/** A tree of 2^DEPTH leaves, with ours at `index` and random others. */
function treeWith(leaf, index) {
  const leaves = Array.from({ length: 2 ** DEPTH }, (_, i) => (i === index ? leaf : BigInt(1000 + i)))
  const levels = [leaves]
  for (let k = 0; k < DEPTH; k++) {
    const below = levels[k]
    levels.push(Array.from({ length: below.length / 2 }, (_, i) => H(below[2 * i], below[2 * i + 1])))
  }
  const pathElements = []
  const pathIndices = []
  let pos = index
  for (let k = 0; k < DEPTH; k++) {
    pathIndices.push(pos % 2)
    pathElements.push(levels[k][pos ^ 1].toString())
    pos = Math.floor(pos / 2)
  }
  return { root: levels[DEPTH][0], pathElements, pathIndices }
}

const secret = 123456789012345678901234567890n
const blinding = 987654321n
const birthDay = dayOf('2000-05-17T00:00:00Z')
const expiryDay = dayOf('2027-09-01T00:00:00Z')
const today = dayOf('2026-09-28T00:00:00Z')
const cutoffDay = dayOf('2008-09-28T00:00:00Z') // born on or before: 18 today
const leaf = H(LEAF_TAG, H(secret, blinding), birthDay, expiryDay)
const tree = treeWith(leaf, 5)

const base = {
  holderSecret: secret.toString(),
  holderBlinding: blinding.toString(),
  birthDay,
  expiryDay,
  pathElements: tree.pathElements,
  pathIndices: tree.pathIndices,
  today,
  cutoffDay,
  challenge: '4242',
  scope: '0',
}

async function witness(input) {
  const file = join(work, `w${Math.random().toString(36).slice(2)}.wtns`)
  await snarkjs.wtns.calculate(input, wasm, file)
  if (!(await snarkjs.wtns.check(r1cs, file, { info() {}, warn() {}, error() {}, debug() {} }))) {
    throw new Error('witness does not satisfy the constraints')
  }
  const w = await snarkjs.wtns.exportJson(file)
  return { root: w[1], nym: w[2] }
}

let failures = 0
async function expectOk(name, input, check) {
  try {
    const out = await witness(input)
    check?.(out)
    console.log(`ok    ${name}`)
  } catch (error) {
    failures++
    console.log(`FAIL  ${name}: ${error.message}`)
  }
}
async function expectReject(name, input) {
  try {
    await witness(input)
    failures++
    console.log(`FAIL  ${name}: accepted`)
  } catch {
    console.log(`ok    ${name} (rejected)`)
  }
}

await expectOk('valid proof, no scope: root matches, nym is 0', base, (out) => {
  if (out.root !== tree.root) throw new Error('root mismatch')
  if (out.nym !== 0n) throw new Error('nym must be 0 without a scope')
})
await expectOk('scoped nym is Poseidon(NYM_TAG, secret, scope)', { ...base, scope: '77' }, (out) => {
  if (out.nym !== H(NYM_TAG, secret, 77n)) throw new Error('nym mismatch')
})
await expectOk('born exactly on the cutoff day', { ...base, cutoffDay: birthDay })
await expectReject('born one day after the cutoff', { ...base, cutoffDay: birthDay - 1 })
await expectReject('credential expired yesterday', { ...base, today: expiryDay + 1 })
/*
 * `root` is an output: a witness with a different birth day or secret is
 * internally consistent but lands on a root the issuer never published, and
 * the verifier's root check refuses it. Assert the root moves.
 */
async function expectForeignRoot(name, input) {
  try {
    const out = await witness(input)
    if (out.root === tree.root) throw new Error('reproduced the issuer root')
    console.log(`ok    ${name} (root differs from the issuer's)`)
  } catch (error) {
    if (error.message === 'reproduced the issuer root') {
      failures++
      console.log(`FAIL  ${name}: ${error.message}`)
    } else {
      console.log(`ok    ${name} (rejected)`)
    }
  }
}
await expectForeignRoot('birth day other than the attested one', { ...base, birthDay: birthDay - 3650 })
await expectForeignRoot('wrong holder secret (stolen leaf data, no secret)', {
  ...base, holderSecret: (secret + 1n).toString(),
})
await expectReject('non-binary path index', { ...base, pathIndices: [2, ...tree.pathIndices.slice(1)] })
await expectReject('17-bit range: cutoff wrapped past the field', {
  ...base, cutoffDay: (p.F.p - 1n).toString(),
})

console.log(failures === 0 ? '\nall checks passed' : `\n${failures} check(s) failed`)
process.exit(failures === 0 ? 0 : 1)
