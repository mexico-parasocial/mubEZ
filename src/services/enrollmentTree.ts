import { createHash } from 'node:crypto'
import { getDb } from '../db/connection.js'
// @ts-expect-error — no ESM types available for circomlibjs
import { buildPoseidon } from 'circomlibjs'

/*
 * The issuer's enrollment tree (CD-16).
 *
 * A binary Poseidon(2) Merkle tree over enrollment commitments, in issuance
 * order. A leaf holds its commitment while an active INE artifact carries it,
 * and zero otherwise, so revoking or expiring an enrollment removes it from
 * the next root. Nullifier proofs (nullifier_proof_v2) show membership against
 * a root instead of revealing the commitment; every enrolled person shares
 * the root.
 *
 * The tree is public (GET /identity/enrollment-tree): clients download all of
 * it and pick their own path, so fetching it says nothing about which leaf is
 * theirs. Leaves are Poseidon(birthYear, salt) with a 248-bit salt, which
 * hides the birth year.
 *
 * ENROLLMENT_TREE_DEPTH must equal the depth compiled into the circuit.
 * 14 fits the development Powers of Tau (2^12 constraints); production uses
 * the depth fixed by the setup ceremony (docs/ZK_CEREMONY_PLAN.md).
 */

export const ENROLLMENT_TREE_DEPTH = 14
export const ENROLLMENT_TREE_CAPACITY = 2 ** ENROLLMENT_TREE_DEPTH

/**
 * How long a root stays acceptable after a newer one replaces it. Bounds how
 * long a revoked enrollment can still prove membership, and how stale a
 * client's copy of the tree may be.
 */
export const ENROLLMENT_ROOT_GRACE_SEC = 60 * 60

export type EnrollmentTree = {
  depth: number
  root: string
  /** levels[0] are the leaves in index order; levels[k] the populated nodes at height k. */
  levels: string[][]
  /** zeros[k]: the root of an empty subtree of height k, used past the end of each level. */
  zeros: string[]
}

type Poseidon = Awaited<ReturnType<typeof buildPoseidon>>
let poseidonPromise: Promise<Poseidon> | null = null
const poseidon = () => (poseidonPromise ??= buildPoseidon())

function hashPair(p: Poseidon, left: string, right: string): string {
  return p.F.toString(p([BigInt(left), BigInt(right)]))
}

let zerosCache: string[] | null = null
async function zeros(): Promise<string[]> {
  if (zerosCache) return zerosCache
  const p = await poseidon()
  const out = ['0']
  for (let k = 0; k < ENROLLMENT_TREE_DEPTH; k += 1) out.push(hashPair(p, out[k], out[k]))
  zerosCache = out
  return out
}

/** Builds the tree over `leaves` (index order, '0' for an empty or revoked leaf). */
export async function buildEnrollmentTree(leaves: string[]): Promise<EnrollmentTree> {
  if (leaves.length > ENROLLMENT_TREE_CAPACITY) {
    throw new Error(`Enrollment tree is full (${ENROLLMENT_TREE_CAPACITY} leaves)`)
  }
  const p = await poseidon()
  const z = await zeros()
  const levels: string[][] = [leaves.slice()]
  for (let k = 0; k < ENROLLMENT_TREE_DEPTH; k += 1) {
    const below = levels[k]
    const above: string[] = []
    for (let i = 0; i < below.length; i += 2) {
      above.push(hashPair(p, below[i], below[i + 1] ?? z[k]))
    }
    levels.push(above)
  }
  const root = levels[ENROLLMENT_TREE_DEPTH][0] ?? z[ENROLLMENT_TREE_DEPTH]
  return { depth: ENROLLMENT_TREE_DEPTH, root, levels: levels.slice(0, ENROLLMENT_TREE_DEPTH), zeros: z }
}

/** The authentication path for the leaf holding `commitment`, or null when it is not an active leaf. */
export function enrollmentPath(tree: EnrollmentTree, commitment: string) {
  const index = tree.levels[0].indexOf(commitment)
  if (index < 0 || commitment === '0') return null
  const pathElements: string[] = []
  const pathIndices: number[] = []
  let position = index
  for (let k = 0; k < tree.depth; k += 1) {
    pathIndices.push(position % 2)
    pathElements.push(tree.levels[k][position ^ 1] ?? tree.zeros[k])
    position = Math.floor(position / 2)
  }
  return { leafIndex: index, pathElements, pathIndices }
}

/** Current leaf values: the commitment while an active INE artifact carries it, else '0'. */
function currentLeaves(): string[] {
  const rows = getDb().prepare(`
    SELECT l.leaf_index, l.commitment,
      EXISTS (
        SELECT 1 FROM proof_artifacts a
        WHERE a.commitment = l.commitment
          AND a.request_id = 'ine-verification'
          AND a.status = 'active'
          AND (a.expires_at IS NULL OR a.expires_at > ?)
      ) AS active
    FROM enrollment_leaves l
    ORDER BY l.leaf_index
  `).all(new Date().toISOString()) as Array<{ leaf_index: number; commitment: string; active: number }>
  return rows.map((row) => (row.active ? row.commitment : '0'))
}

let cached: { fingerprint: string; tree: EnrollmentTree } | null = null

/**
 * The current tree, rebuilt only when a leaf changed. Records its root, and
 * marks the previous current root superseded, so the acceptance window starts
 * the first time anyone looks after a change.
 */
export async function currentEnrollmentTree(): Promise<EnrollmentTree> {
  const leaves = currentLeaves()
  const fingerprint = createHash('sha256').update(leaves.join(',')).digest('hex')
  const tree = cached?.fingerprint === fingerprint ? cached.tree : await buildEnrollmentTree(leaves)
  cached = { fingerprint, tree }

  const db = getDb()
  const now = new Date().toISOString()
  db.transaction(() => {
    const known = db.prepare('SELECT superseded_at FROM enrollment_roots WHERE root = ?').get(tree.root) as
      | { superseded_at: string | null }
      | undefined
    if (known && known.superseded_at === null) return
    db.prepare('UPDATE enrollment_roots SET superseded_at = ? WHERE superseded_at IS NULL AND root != ?').run(now, tree.root)
    db.prepare(`
      INSERT INTO enrollment_roots (root, first_seen_at, superseded_at) VALUES (?, ?, NULL)
      ON CONFLICT(root) DO UPDATE SET superseded_at = NULL
    `).run(tree.root, now)
  })()
  return tree
}

/** Adds the leaf for a newly issued enrollment. Idempotent per commitment. */
export function addEnrollmentLeaf(commitment: string) {
  getDb().prepare('INSERT OR IGNORE INTO enrollment_leaves (commitment) VALUES (?)').run(commitment)
}

/** A root a nullifier proof may use: the current one, or one superseded within the grace window. */
export async function isAcceptableEnrollmentRoot(root: string): Promise<boolean> {
  const tree = await currentEnrollmentTree()
  if (root === tree.root) return true
  const row = getDb().prepare('SELECT superseded_at FROM enrollment_roots WHERE root = ?').get(root) as
    | { superseded_at: string | null }
    | undefined
  if (!row?.superseded_at) return false
  return Date.now() - Date.parse(row.superseded_at) <= ENROLLMENT_ROOT_GRACE_SEC * 1000
}
