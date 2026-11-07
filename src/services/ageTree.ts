import { createPublicKey, verify } from 'node:crypto'
// @ts-expect-error — no ESM types available for circomlibjs
import { buildPoseidon } from 'circomlibjs'
import { getDb } from '../db/connection.js'
import { dayNumber, issuerToday } from './ageAttestation.js'
import { getIssuerSigner } from './identityWallet.js'
import { FIELD_MODULUS } from './zkpService.js'

/*
 * The issuer age tree: the issuer half of v3 unlinkable age proofs
 * (docs/V3_UNLINKABLE_AGE_PROOFS.md, CD-15, CD-16).
 *
 * A Poseidon Merkle tree of depth 20. Leaf i is
 *
 *     leaf = Poseidon(H, birthDay, expiryDay)
 *
 * where H = Poseidon(s, r) is the wallet's hiding commitment to its device
 * secret, birthDay comes from the INE record (ageAttestation.ts — never from
 * the client), and expiryDay bounds how long the leaf proves anything. Inner
 * nodes are Poseidon(left, right); an empty slot is 0, an empty subtree is
 * the zero hash of its height. That is the Semaphore group layout, so the v3
 * circuit can use circomlib's Poseidon Merkle proof as is.
 *
 * Membership is the issuer binding: only a leaf the issuer inserted is in a
 * root the issuer signed. Revocation zeroes the leaf and publishes a new root;
 * a verifier accepts a root only while it is current or for ROOT_WINDOW_MS
 * after it was superseded, so revocation takes effect within that window.
 *
 * What the issuer publishes reveals nothing about holders: leaves are hiding
 * commitments, and the leaf → enrollment mapping (age_tree_leaves) stays
 * private. Wallets fetch whole chunks of 2^CHUNK_LEVEL leaves and the level
 * above them, never "my path", so the issuer learns at most which chunk a
 * refreshing wallet sits in, and when.
 *
 * The tree is derived state. A leaf is in the tree exactly when it is not
 * replaced, its enrollment is active and unexpired, and its expiryDay has not
 * passed; syncAgeTree() reconciles the nodes with that rule. So every way an
 * enrollment stops being active — the revoke endpoint, a grant revoke, a
 * suspension, a deleted session, expiry — zeroes its leaf without each path
 * having to remember to.
 */

export const AGE_TREE_DEPTH = 20
export const AGE_TREE_CAPACITY = 2 ** AGE_TREE_DEPTH
/** Wallets download subtrees of 2^CHUNK_LEVEL leaves. */
export const AGE_TREE_CHUNK_LEVEL = 10
export const AGE_TREE_CHUNK_SIZE = 2 ** AGE_TREE_CHUNK_LEVEL
export const AGE_TREE_CHUNK_COUNT = AGE_TREE_CAPACITY / AGE_TREE_CHUNK_SIZE
/** Leaves are short-lived and re-issued on request (refreshAgeLeaf). */
export const AGE_LEAF_TTL_DAYS = 28
/** How long a superseded root stays acceptable: the revocation delay W. */
export const AGE_TREE_ROOT_WINDOW_MS = 24 * 60 * 60 * 1000
export const AGE_TREE_ROOT_ALG = 'm8.identity.ageTree.root.v1'
/** Public reads re-check expiry and enrollment status at most this often. */
const READ_SYNC_INTERVAL_MS = 30_000

export class AgeTreeError extends Error {
  constructor(
    readonly code: string,
    readonly status: 400 | 403 | 404 | 409 | 503,
    message: string,
  ) {
    super(message)
  }
}

// ─── Hashing ────────────────────────────────────────────────────────────────

type Poseidon = ((inputs: bigint[]) => unknown) & { F: { toObject(value: unknown): bigint } }

let poseidonPromise: Promise<Poseidon> | null = null
let zeroHashes: bigint[] | null = null

async function poseidon(): Promise<Poseidon> {
  if (!poseidonPromise) poseidonPromise = buildPoseidon() as Promise<Poseidon>
  const instance = await poseidonPromise
  if (!zeroHashes) {
    const zeros = [0n]
    for (let level = 0; level < AGE_TREE_DEPTH; level++) {
      zeros.push(instance.F.toObject(instance([zeros[level], zeros[level]])))
    }
    zeroHashes = zeros
  }
  return instance
}

function hashWith(instance: Poseidon, inputs: bigint[]): bigint {
  return instance.F.toObject(instance(inputs))
}

/** Root of an empty subtree of height `level` (level 0: an empty leaf, 0). */
export async function ageTreeZeroHash(level: number): Promise<bigint> {
  await poseidon()
  return zeroHashes![level]
}

export async function hashAgeTreeNode(left: bigint, right: bigint): Promise<bigint> {
  return hashWith(await poseidon(), [left, right])
}

/** leaf = Poseidon(H, birthDay, expiryDay). */
export async function computeAgeLeaf(leafCommitment: bigint, birthDay: number, expiryDay: number): Promise<bigint> {
  return hashWith(await poseidon(), [leafCommitment, BigInt(birthDay), BigInt(expiryDay)])
}

const DECIMAL = /^(0|[1-9][0-9]{0,77})$/

/** H as sent by a wallet: a canonical decimal, non-zero BN254 field element. */
export function parseLeafCommitment(value: unknown): bigint | null {
  if (typeof value !== 'string' || !DECIMAL.test(value)) return null
  const n = BigInt(value)
  return n > 0n && n < FIELD_MODULUS ? n : null
}

// ─── Signed roots ───────────────────────────────────────────────────────────

export interface SignedAgeTreeRoot {
  alg: typeof AGE_TREE_ROOT_ALG
  version: number
  depth: number
  /** Leaf slots used so far (the next leaf index). */
  size: number
  /** Decimal field element. */
  root: string
  issuedAt: string
  issuerDid: string
  keyId: string
  /** Ed25519 over encodeAgeTreeRoot(), base64url. */
  signature: string
}

export type AcceptableAgeTreeRoot = SignedAgeTreeRoot & {
  /** When a newer root replaced this one; null for the current root. */
  supersededAt: string | null
}

/** The bytes the issuer signs. Field order is part of the format. */
export function encodeAgeTreeRoot(root: Omit<SignedAgeTreeRoot, 'signature'>): Uint8Array {
  return new TextEncoder().encode([
    root.alg,
    root.issuerDid,
    root.keyId,
    String(root.depth),
    String(root.version),
    String(root.size),
    root.root,
    root.issuedAt,
  ].join('\n'))
}

/** Check a root's signature against an issuer public key (SPKI PEM, from /v1/issuers). */
export function verifyAgeTreeRootSignature(root: SignedAgeTreeRoot, publicKeyPem: string): boolean {
  if (root.alg !== AGE_TREE_ROOT_ALG) return false
  try {
    const { signature, ...unsigned } = root
    return verify(null, encodeAgeTreeRoot(unsigned), createPublicKey(publicKeyPem), Buffer.from(signature, 'base64url'))
  } catch {
    return false
  }
}

type RootRow = {
  version: number
  root: string
  size: number
  issued_at: string
  issuer_did: string | null
  key_id: string | null
  signature: string | null
}

function rowToSignedRoot(row: RootRow): SignedAgeTreeRoot {
  return {
    alg: AGE_TREE_ROOT_ALG,
    version: row.version,
    depth: AGE_TREE_DEPTH,
    size: row.size,
    root: row.root,
    issuedAt: row.issued_at,
    issuerDid: row.issuer_did!,
    keyId: row.key_id!,
    signature: row.signature!,
  }
}

async function signPendingRoots(): Promise<void> {
  const db = getDb()
  const pending = db
    .prepare('SELECT * FROM age_tree_roots WHERE signature IS NULL ORDER BY version')
    .all() as RootRow[]
  if (pending.length === 0) return
  const signer = getIssuerSigner()
  const info = await signer.getInfo()
  for (const row of pending) {
    const unsigned = {
      alg: AGE_TREE_ROOT_ALG,
      version: row.version,
      depth: AGE_TREE_DEPTH,
      size: row.size,
      root: row.root,
      issuedAt: row.issued_at,
      issuerDid: info.did,
      keyId: info.keyId,
    } as const
    const signature = Buffer.from(await signer.sign(encodeAgeTreeRoot(unsigned))).toString('base64url')
    db.prepare(
      'UPDATE age_tree_roots SET issuer_did = ?, key_id = ?, signature = ? WHERE version = ? AND signature IS NULL'
    ).run(info.did, info.keyId, signature, row.version)
  }
}

// ─── Reconciliation ─────────────────────────────────────────────────────────

let lastSyncAt = 0

/**
 * Bring the tree in line with the leaves' state (see the header), publish a
 * new version if anything changed, and sign every unsigned version.
 *
 * `force: false` skips the reconciliation when one ran in the last
 * READ_SYNC_INTERVAL_MS; mutations always force it.
 */
export async function syncAgeTree(opts: { force?: boolean; now?: Date } = {}): Promise<SignedAgeTreeRoot | null> {
  const now = opts.now ?? new Date()
  if (opts.force || now.getTime() - lastSyncAt >= READ_SYNC_INTERVAL_MS) {
    const instance = await poseidon()
    reconcile(instance, now)
    lastSyncAt = now.getTime()
  }
  await signPendingRoots()
  return latestSignedAgeTreeRoot()
}

function reconcile(instance: Poseidon, now: Date): void {
  const db = getDb()
  const zeros = zeroHashes!
  const today = dayNumber(issuerToday(now))
  const nowIso = now.toISOString()

  db.transaction(() => {
    const dirty = db.prepare(`
      SELECT leaf_index, leaf, want FROM (
        SELECT l.leaf_index, l.leaf, l.in_tree,
          CASE WHEN l.status = 'active'
                AND p.status = 'active'
                AND l.expiry_day >= @today
                AND (p.expires_at IS NULL OR p.expires_at > @nowIso)
               THEN 1 ELSE 0 END AS want
        FROM age_tree_leaves l
        LEFT JOIN proof_artifacts p ON p.id = l.proof_artifact_id
      ) WHERE want != in_tree
    `).all({ today, nowIso }) as Array<{ leaf_index: number; leaf: string; want: number }>

    const hasRoot = db.prepare('SELECT 1 FROM age_tree_roots LIMIT 1').get()
    if (dirty.length === 0 && hasRoot) return

    const getNode = db.prepare('SELECT hash FROM age_tree_nodes WHERE level = ? AND node_index = ?').pluck()
    const putNode = db.prepare(
      'INSERT INTO age_tree_nodes (level, node_index, hash) VALUES (?, ?, ?) ON CONFLICT (level, node_index) DO UPDATE SET hash = excluded.hash'
    )
    const dropNode = db.prepare('DELETE FROM age_tree_nodes WHERE level = ? AND node_index = ?')
    const node = (level: number, index: number): bigint => {
      const hash = getNode.get(level, index) as string | undefined
      return hash === undefined ? zeros[level] : BigInt(hash)
    }
    // Sparse: a node equal to its zero subtree is not stored.
    const setNode = (level: number, index: number, value: bigint) => {
      if (value === zeros[level]) dropNode.run(level, index)
      else putNode.run(level, index, value.toString())
    }

    const setInTree = db.prepare('UPDATE age_tree_leaves SET in_tree = ? WHERE leaf_index = ?')
    let touched = new Set<number>()
    for (const row of dirty) {
      setNode(0, row.leaf_index, row.want ? BigInt(row.leaf) : 0n)
      setInTree.run(row.want, row.leaf_index)
      touched.add(row.leaf_index)
    }
    // Recompute only the paths above changed leaves, one level at a time.
    for (let level = 0; level < AGE_TREE_DEPTH; level++) {
      const parents = new Set<number>()
      for (const index of touched) parents.add(index >> 1)
      for (const parent of parents) {
        const left = node(level, parent * 2)
        const right = node(level, parent * 2 + 1)
        const value = left === zeros[level] && right === zeros[level]
          ? zeros[level + 1]
          : hashWith(instance, [left, right])
        setNode(level + 1, parent, value)
      }
      touched = parents
    }

    const root = node(AGE_TREE_DEPTH, 0)
    const size = (db.prepare('SELECT COALESCE(MAX(leaf_index) + 1, 0) FROM age_tree_leaves').pluck().get() as number)
    const version = (db.prepare('SELECT COALESCE(MAX(version), 0) + 1 FROM age_tree_roots').pluck().get() as number)
    db.prepare('INSERT INTO age_tree_roots (version, root, size, issued_at) VALUES (?, ?, ?, ?)')
      .run(version, root.toString(), size, nowIso)
  })()
}

// ─── Issuance and refresh ───────────────────────────────────────────────────

export interface IssuedAgeLeaf {
  leafIndex: number
  birthDay: number
  expiryDay: number
  /** The signed root that first contains the leaf. */
  root: SignedAgeTreeRoot
}

/**
 * A leaf is valid through `expiryDay`, a day on the issuer's calendar
 * (ISSUER_TIME_ZONE), which is also the calendar a v3 verifier's `today` is
 * on. It never outlives its enrollment: the issuer-calendar day the
 * enrollment ends in is excluded, since it may end early in that day.
 */
function expiryDayFor(today: number, enrollmentExpiresAt: string | null): number {
  const ttlExpiry = today + AGE_LEAF_TTL_DAYS
  if (!enrollmentExpiresAt) return ttlExpiry
  const end = new Date(enrollmentExpiresAt)
  if (Number.isNaN(end.getTime())) return today - 1 // unreadable end: issue nothing
  return Math.min(ttlExpiry, dayNumber(issuerToday(end)) - 1)
}

function insertLeaf(proofArtifactId: string, leaf: bigint, expiryDay: number): number {
  const db = getDb()
  const leafIndex = db.prepare('SELECT COALESCE(MAX(leaf_index) + 1, 0) FROM age_tree_leaves').pluck().get() as number
  if (leafIndex >= AGE_TREE_CAPACITY) {
    throw new AgeTreeError('AGE_TREE_FULL', 503, 'The age tree is full')
  }
  db.prepare(
    'INSERT INTO age_tree_leaves (leaf_index, leaf, proof_artifact_id, expiry_day) VALUES (?, ?, ?, ?)'
  ).run(leafIndex, leaf.toString(), proofArtifactId, expiryDay)
  return leafIndex
}

async function publishedRootFor(now: Date): Promise<SignedAgeTreeRoot> {
  const root = await syncAgeTree({ force: true, now })
  if (!root) throw new AgeTreeError('AGE_TREE_UNSIGNED', 503, 'The age tree root could not be signed')
  return root
}

/**
 * Add a leaf for a just-recorded INE enrollment. `birthDay` must come from the
 * INE record (attestAgeFromIneBirthDate), never from the client.
 */
export async function appendAgeLeaf(input: {
  proofArtifactId: string
  leafCommitment: bigint
  birthDay: number
  enrollmentExpiresAt: string | null
  now?: Date
}): Promise<IssuedAgeLeaf> {
  const now = input.now ?? new Date()
  const today = dayNumber(issuerToday(now))
  const expiryDay = expiryDayFor(today, input.enrollmentExpiresAt)
  if (expiryDay < today) {
    throw new AgeTreeError('AGE_LEAF_ENROLLMENT_INACTIVE', 403, 'The enrollment ends before an age leaf could be used')
  }
  const leaf = await computeAgeLeaf(input.leafCommitment, input.birthDay, expiryDay)
  const leafIndex = getDb().transaction(() => insertLeaf(input.proofArtifactId, leaf, expiryDay))()
  const root = await publishedRootFor(now)
  return { leafIndex, birthDay: input.birthDay, expiryDay, root }
}

/**
 * Re-issue a leaf with a fresh expiry. The holder proves the old leaf is
 * theirs by sending its preimage (H, birthDay, expiryDay): the issuer keeps
 * no birth date, only the leaf hash, so a matching preimage is also what
 * carries the issuer-attested birthDay over. The old leaf is replaced and
 * leaves the tree; the enrollment must still be active and belong to the
 * session.
 */
export async function refreshAgeLeaf(
  sessionId: string,
  input: { leafIndex: number; leafCommitment: bigint; birthDay: number; expiryDay: number },
  now: Date = new Date(),
): Promise<IssuedAgeLeaf> {
  const db = getDb()
  const row = db.prepare(`
    SELECT l.leaf, l.status, l.proof_artifact_id, p.session_id, p.status AS artifact_status, p.expires_at
    FROM age_tree_leaves l
    LEFT JOIN proof_artifacts p ON p.id = l.proof_artifact_id
    WHERE l.leaf_index = ?
  `).get(input.leafIndex) as {
    leaf: string
    status: string
    proof_artifact_id: string
    session_id: string | null
    artifact_status: string | null
    expires_at: string | null
  } | undefined

  // Someone else's leaf reads as absent, not as forbidden.
  if (!row || row.session_id !== sessionId) {
    throw new AgeTreeError('AGE_LEAF_NOT_FOUND', 404, 'Age leaf not found')
  }
  const expected = await computeAgeLeaf(input.leafCommitment, input.birthDay, input.expiryDay)
  if (expected.toString() !== row.leaf) {
    throw new AgeTreeError('AGE_LEAF_MISMATCH', 403, 'The leaf preimage does not match')
  }
  if (row.status !== 'active') {
    throw new AgeTreeError('AGE_LEAF_REPLACED', 409, 'This age leaf was already replaced')
  }
  if (row.artifact_status !== 'active' || (row.expires_at !== null && row.expires_at <= now.toISOString())) {
    throw new AgeTreeError('AGE_LEAF_ENROLLMENT_INACTIVE', 403, 'The enrollment behind this age leaf is not active')
  }

  const today = dayNumber(issuerToday(now))
  const expiryDay = expiryDayFor(today, row.expires_at)
  if (expiryDay < today) {
    throw new AgeTreeError('AGE_LEAF_ENROLLMENT_INACTIVE', 403, 'The enrollment ends before an age leaf could be used')
  }
  const leaf = await computeAgeLeaf(input.leafCommitment, input.birthDay, expiryDay)
  const leafIndex = db.transaction(() => {
    const replaced = db
      .prepare("UPDATE age_tree_leaves SET status = 'replaced' WHERE leaf_index = ? AND status = 'active'")
      .run(input.leafIndex)
    if (replaced.changes !== 1) {
      throw new AgeTreeError('AGE_LEAF_REPLACED', 409, 'This age leaf was already replaced')
    }
    return insertLeaf(row.proof_artifact_id, leaf, expiryDay)
  })()
  const root = await publishedRootFor(now)
  return { leafIndex, birthDay: input.birthDay, expiryDay, root }
}

// ─── Public reads ───────────────────────────────────────────────────────────

export function latestSignedAgeTreeRoot(): SignedAgeTreeRoot | null {
  const row = getDb()
    .prepare('SELECT * FROM age_tree_roots WHERE signature IS NOT NULL ORDER BY version DESC LIMIT 1')
    .get() as RootRow | undefined
  return row ? rowToSignedRoot(row) : null
}

/**
 * The roots a verifier should accept now: the current one, and those
 * superseded less than AGE_TREE_ROOT_WINDOW_MS ago. Newest first.
 */
export async function acceptableAgeTreeRoots(now: Date = new Date()): Promise<AcceptableAgeTreeRoot[]> {
  await syncAgeTree({ now })
  const cutoff = new Date(now.getTime() - AGE_TREE_ROOT_WINDOW_MS).toISOString()
  const rows = getDb().prepare(`
    SELECT * FROM (
      SELECT r.*, (
        SELECT MIN(n.issued_at) FROM age_tree_roots n
        WHERE n.version > r.version AND n.signature IS NOT NULL
      ) AS superseded_at
      FROM age_tree_roots r
      WHERE r.signature IS NOT NULL
    )
    WHERE superseded_at IS NULL OR superseded_at > ?
    ORDER BY version DESC
  `).all(cutoff) as Array<RootRow & { superseded_at: string | null }>
  return rows.map((row) => ({ ...rowToSignedRoot(row), supersededAt: row.superseded_at }))
}

/** Verifier check for a v3 proof's public `root`. */
export async function isAcceptableAgeTreeRoot(root: string, now: Date = new Date()): Promise<boolean> {
  return (await acceptableAgeTreeRoots(now)).some((candidate) => candidate.root === root)
}

export interface AgeTreeSnapshot {
  /** Tree version the values belong to; its signed root is in /roots once published. */
  version: number
  root: string
  size: number
}

function currentSnapshot(): AgeTreeSnapshot {
  const row = getDb()
    .prepare('SELECT version, root, size FROM age_tree_roots ORDER BY version DESC LIMIT 1')
    .get() as { version: number; root: string; size: number } | undefined
  if (!row) throw new AgeTreeError('AGE_TREE_UNSIGNED', 503, 'The age tree has not been published yet')
  return row
}

/**
 * Leaves [chunk * CHUNK_SIZE, (chunk + 1) * CHUNK_SIZE), as decimal strings;
 * zeroed and unused slots read "0", and slots past `size` are omitted.
 */
export async function ageTreeChunk(chunk: number): Promise<AgeTreeSnapshot & { chunk: number; start: number; leaves: string[] }> {
  if (!Number.isInteger(chunk) || chunk < 0 || chunk >= AGE_TREE_CHUNK_COUNT) {
    throw new AgeTreeError('AGE_TREE_CHUNK_INVALID', 400, `chunk must be an integer in [0, ${AGE_TREE_CHUNK_COUNT})`)
  }
  await syncAgeTree()
  const db = getDb()
  return db.transaction(() => {
    const snapshot = currentSnapshot()
    const start = chunk * AGE_TREE_CHUNK_SIZE
    const end = Math.min(start + AGE_TREE_CHUNK_SIZE, snapshot.size)
    const leaves = end > start ? new Array<string>(end - start).fill('0') : []
    const rows = db
      .prepare('SELECT node_index, hash FROM age_tree_nodes WHERE level = 0 AND node_index >= ? AND node_index < ?')
      .all(start, end) as Array<{ node_index: number; hash: string }>
    for (const row of rows) leaves[row.node_index - start] = row.hash
    return { ...snapshot, chunk, start, leaves }
  })()
}

/**
 * The nodes at AGE_TREE_CHUNK_LEVEL — one per chunk, up to the last used
 * chunk. With a chunk, enough to rebuild a full path without naming a leaf.
 */
export async function ageTreeChunkRoots(): Promise<AgeTreeSnapshot & { level: number; nodes: string[] }> {
  await syncAgeTree()
  const db = getDb()
  const zeros = zeroHashes!
  return db.transaction(() => {
    const snapshot = currentSnapshot()
    const count = Math.ceil(snapshot.size / AGE_TREE_CHUNK_SIZE)
    const nodes = new Array<string>(count).fill(zeros[AGE_TREE_CHUNK_LEVEL].toString())
    const rows = db
      .prepare('SELECT node_index, hash FROM age_tree_nodes WHERE level = ? AND node_index < ?')
      .all(AGE_TREE_CHUNK_LEVEL, count) as Array<{ node_index: number; hash: string }>
    for (const row of rows) nodes[row.node_index] = row.hash
    return { ...snapshot, level: AGE_TREE_CHUNK_LEVEL, nodes }
  })()
}

// ─── Wallet-side path reconstruction ────────────────────────────────────────

export interface AgeTreeMerklePath {
  /** Sibling hashes from the leaf up, AGE_TREE_DEPTH of them. */
  pathElements: string[]
  /** 0 when the node on the path is a left child, 1 when right. */
  pathIndices: number[]
  root: string
}

async function subtreePath(values: bigint[], index: number, height: number, baseLevel: number) {
  await poseidon()
  const zeros = zeroHashes!
  const elements: bigint[] = []
  const indices: number[] = []
  let level = values.slice()
  let position = index
  for (let h = 0; h < height; h++) {
    const zero = zeros[baseLevel + h]
    const width = 1 << (height - h)
    while (level.length < width) level.push(zero)
    elements.push(level[position ^ 1])
    indices.push(position & 1)
    const next: bigint[] = []
    for (let i = 0; i < width; i += 2) {
      next.push(level[i] === zero && level[i + 1] === zero ? zeros[baseLevel + h + 1] : await hashAgeTreeNode(level[i], level[i + 1]))
    }
    level = next
    position >>= 1
  }
  return { elements, indices, root: level[0] }
}

/**
 * What a wallet does with the public data: rebuild its Merkle path from its
 * chunk's leaves and the chunk roots, without having asked for its own path.
 * Pure; exported for wallets' conformance tests and our own.
 */
export async function merklePathFromChunks(
  leafIndex: number,
  chunkLeaves: string[],
  chunkRoots: string[],
): Promise<AgeTreeMerklePath> {
  const inChunk = await subtreePath(
    chunkLeaves.map(BigInt),
    leafIndex % AGE_TREE_CHUNK_SIZE,
    AGE_TREE_CHUNK_LEVEL,
    0,
  )
  const chunk = Math.floor(leafIndex / AGE_TREE_CHUNK_SIZE)
  const tops = chunkRoots.map(BigInt)
  if (tops[chunk] !== inChunk.root) {
    throw new Error('Chunk does not match the chunk roots: the two reads come from different tree versions')
  }
  const above = await subtreePath(tops, chunk, AGE_TREE_DEPTH - AGE_TREE_CHUNK_LEVEL, AGE_TREE_CHUNK_LEVEL)
  return {
    pathElements: [...inChunk.elements, ...above.elements].map(String),
    pathIndices: [...inChunk.indices, ...above.indices],
    root: above.root.toString(),
  }
}

/** The check the v3 circuit makes: does `leaf` hash up to `root` along the path? */
export async function verifyAgeTreeMerklePath(leaf: string, path: AgeTreeMerklePath): Promise<boolean> {
  if (path.pathElements.length !== AGE_TREE_DEPTH || path.pathIndices.length !== AGE_TREE_DEPTH) return false
  let current = BigInt(leaf)
  for (let level = 0; level < AGE_TREE_DEPTH; level++) {
    const sibling = BigInt(path.pathElements[level])
    current = path.pathIndices[level] === 0
      ? await hashAgeTreeNode(current, sibling)
      : await hashAgeTreeNode(sibling, current)
  }
  return current.toString() === path.root
}
