import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-age-tree-'))
process.env.DATABASE_PATH = join(tmpDir, 'age-tree.db')

const issuerKeys = generateKeyPairSync('ed25519')
process.env.IDENTITY_ISSUER_DID = 'did:m8:ine:age-tree-test'
process.env.IDENTITY_ISSUER_KEY_ID = 'age-tree-test-key'
process.env.IDENTITY_ISSUER_PRIVATE_JWK = JSON.stringify(issuerKeys.privateKey.export({ format: 'jwk' }))
process.env.IDENTITY_ISSUER_PUBLIC_JWK = JSON.stringify(issuerKeys.publicKey.export({ format: 'jwk' }))
const issuerPublicKeyPem = issuerKeys.publicKey.export({ type: 'spki', format: 'pem' }).toString()

type AgeTree = typeof import('../../src/services/ageTree.js')

const DAY = 86_400_000
// Real time: public reads sync against the real clock, which would expire
// leaves issued at a fixed date in the past.
const NOW = new Date()
const inDays = (days: number) => new Date(NOW.getTime() + days * DAY)

describe('issuer age tree (v3 issuer side, CD-16)', () => {
  let tree: AgeTree
  let getDb: typeof import('../../src/db/connection.js').getDb
  let closeDb: typeof import('../../src/db/connection.js').closeDb
  let today: number
  const H = [11n, 22n, 33n].map((n) => n * 1_000_000_007n)
  const BIRTH_DAY = 39_000 // 2006-10-12

  function insertEnrollment(id: string, sessionId: string, expiresAt: string) {
    const db = getDb()
    db.prepare(`
      INSERT INTO proof_artifacts
        (id, session_id, grant_id, request_id, claim_type, outcome, statement, audience_app_id, audience_app_name, surface, status, issued_at, expires_at, revocation_hash, commitment)
      VALUES (?, ?, 'grant-age-tree', 'ine-verification', 'has_para_verification', 'verified', 'test', 'para.identity', 'PARA Identity', 'civic', 'active', ?, ?, ?, ?)
    `).run(id, sessionId, NOW.toISOString(), expiresAt, `rev-${id}`, `${id.length}${Date.now()}${Math.random()}`.replace('.', ''))
  }

  /** What a wallet does: two public reads, then its path. */
  async function walletPath(leafIndex: number) {
    const chunk = await tree.ageTreeChunk(Math.floor(leafIndex / tree.AGE_TREE_CHUNK_SIZE))
    const tops = await tree.ageTreeChunkRoots()
    assert.equal(chunk.version, tops.version)
    return { chunk, path: await tree.merklePathFromChunks(leafIndex, chunk.leaves, tops.nodes) }
  }

  before(async () => {
    ;({ getDb, closeDb } = await import('../../src/db/connection.js'))
    const { ensureSchema, runMigrations } = await import('../../src/db/migrate.js')
    ensureSchema()
    runMigrations()
    tree = await import('../../src/services/ageTree.js')
    const { dayNumber, issuerToday } = await import('../../src/services/ageAttestation.js')
    today = dayNumber(issuerToday(NOW))

    const db = getDb()
    const now = NOW.toISOString()
    for (const sessionId of ['session-a', 'session-b']) {
      db.prepare(`
        INSERT INTO sessions
          (session_id, did, handle, display_name, authorization_server, authenticated_at, pds_safety_json, active_persona_id, active_surface_id, created_at, updated_at, status)
        VALUES (?, ?, ?, ?, 'https://pds.test', ?, '{}', 'orbit', 'public', ?, ?, 'active')
      `).run(sessionId, `did:plc:${sessionId}`, `${sessionId}.test`, sessionId, now, now, now)
    }
    db.prepare(`
      INSERT INTO grants (id, session_id, app_id, app_name, app_kind, surface, requested_claims_json, proof_mode, status, reason, requested_at)
      VALUES ('grant-age-tree', 'session-a', 'para.identity', 'PARA Identity', 'Verifier', 'civic', '[]', 'proof-only', 'approved', 'test', ?)
    `).run(now)
    const yearOut = inDays(365).toISOString()
    insertEnrollment('proof-a0', 'session-a', yearOut)
    insertEnrollment('proof-a1', 'session-a', yearOut)
    insertEnrollment('proof-b0', 'session-b', yearOut)
    insertEnrollment('proof-short', 'session-a', inDays(10).toISOString())
  })

  after(() => closeDb())

  it('accepts only canonical non-zero field elements as H', () => {
    assert.equal(tree.parseLeafCommitment('42'), 42n)
    for (const bad of ['0', '042', '-1', '1e3', ' 1', '21888242871839275222246405745257275088548364400416034343698204186575808495617', 42]) {
      assert.equal(tree.parseLeafCommitment(bad), null, String(bad))
    }
  })

  it('publishes a signed root for the empty tree', async () => {
    const root = await tree.syncAgeTree({ force: true, now: NOW })
    assert.ok(root)
    assert.equal(root.version, 1)
    assert.equal(root.size, 0)
    assert.equal(root.depth, 20)
    assert.equal(root.root, (await tree.ageTreeZeroHash(20)).toString())
    assert.equal(root.issuerDid, 'did:m8:ine:age-tree-test')
    assert.equal(root.keyId, 'age-tree-test-key')
    assert.ok(tree.verifyAgeTreeRootSignature(root, issuerPublicKeyPem))
    // Every signed field is covered.
    assert.equal(tree.verifyAgeTreeRootSignature({ ...root, root: '1' }, issuerPublicKeyPem), false)
    assert.equal(tree.verifyAgeTreeRootSignature({ ...root, size: 1 }, issuerPublicKeyPem), false)
    assert.equal(tree.verifyAgeTreeRootSignature({ ...root, issuedAt: inDays(1).toISOString() }, issuerPublicKeyPem), false)
    assert.equal(tree.verifyAgeTreeRootSignature(root, generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString()), false)
  })

  it('inserts leaves that a wallet can prove membership of from public chunks alone', async () => {
    const issued = []
    for (const [i, id] of ['proof-a0', 'proof-a1', 'proof-b0'].entries()) {
      issued.push(await tree.appendAgeLeaf({
        proofArtifactId: id, leafCommitment: H[i], birthDay: BIRTH_DAY, enrollmentExpiresAt: inDays(365).toISOString(), now: NOW,
      }))
    }
    assert.deepEqual(issued.map((leaf) => leaf.leafIndex), [0, 1, 2])
    assert.deepEqual(issued.map((leaf) => leaf.root.version), [2, 3, 4])
    for (const leaf of issued) {
      assert.equal(leaf.birthDay, BIRTH_DAY)
      assert.equal(leaf.expiryDay, today + tree.AGE_LEAF_TTL_DAYS)
      assert.ok(tree.verifyAgeTreeRootSignature(leaf.root, issuerPublicKeyPem))
    }

    const latest = issued[2].root
    assert.equal(latest.size, 3)
    for (const [i, leaf] of issued.entries()) {
      const { chunk, path } = await walletPath(leaf.leafIndex)
      const expected = await tree.computeAgeLeaf(H[i], BIRTH_DAY, leaf.expiryDay)
      assert.equal(chunk.leaves[leaf.leafIndex], expected.toString())
      assert.equal(path.root, latest.root)
      assert.ok(await tree.verifyAgeTreeMerklePath(expected.toString(), path))
      // The path does not prove a different leaf.
      assert.equal(await tree.verifyAgeTreeMerklePath((expected + 1n).toString(), path), false)
    }
    // Slots past `size` are not served.
    assert.equal((await tree.ageTreeChunk(0)).leaves.length, 3)
    assert.deepEqual((await tree.ageTreeChunk(5)).leaves, [])
  })

  it('never lets a leaf outlive its enrollment', async () => {
    const leaf = await tree.appendAgeLeaf({
      proofArtifactId: 'proof-short', leafCommitment: 77n, birthDay: BIRTH_DAY, enrollmentExpiresAt: inDays(10).toISOString(), now: NOW,
    })
    assert.equal(leaf.expiryDay, today + 9)
  })

  it('keeps one live leaf per enrollment', async () => {
    await assert.rejects(
      tree.appendAgeLeaf({ proofArtifactId: 'proof-a0', leafCommitment: 99n, birthDay: BIRTH_DAY, enrollmentExpiresAt: null, now: NOW }),
      /UNIQUE constraint failed/,
    )
  })

  it('zeroes a revoked enrollment\'s leaf and keeps the old root acceptable only within the window', async () => {
    const before = tree.latestSignedAgeTreeRoot()!
    getDb().prepare("UPDATE proof_artifacts SET status = 'revoked', revoked_at = ? WHERE id = 'proof-a1'").run(NOW.toISOString())
    const after = (await tree.syncAgeTree({ force: true, now: NOW }))!
    assert.equal(after.version, before.version + 1)
    assert.notEqual(after.root, before.root)
    assert.equal(after.size, before.size, 'zeroing frees no slot')

    const { chunk, path } = await walletPath(0)
    assert.equal(chunk.leaves[1], '0')
    assert.equal(path.root, after.root, 'other holders\' paths follow the new root')
    assert.ok(await tree.verifyAgeTreeMerklePath(chunk.leaves[0], path))

    const acceptable = await tree.acceptableAgeTreeRoots(NOW)
    assert.equal(acceptable[0].root, after.root)
    assert.equal(acceptable[0].supersededAt, null)
    assert.ok(await tree.isAcceptableAgeTreeRoot(before.root, NOW))
    assert.ok(await tree.isAcceptableAgeTreeRoot(before.root, inDays(0.9)))
    assert.equal(await tree.isAcceptableAgeTreeRoot(before.root, inDays(1.1)), false, 'the revocation takes effect within W')
    assert.ok(await tree.isAcceptableAgeTreeRoot(after.root, inDays(1.1)), 'the current root never ages out')
    assert.equal(await tree.isAcceptableAgeTreeRoot('12345', NOW), false)
  })

  it('refreshes a leaf only for its own session and on its exact preimage', async () => {
    const expiryDay = today + tree.AGE_LEAF_TTL_DAYS
    const later = inDays(20)
    await assert.rejects(
      tree.refreshAgeLeaf('session-b', { leafIndex: 0, leafCommitment: H[0], birthDay: BIRTH_DAY, expiryDay }, later),
      { code: 'AGE_LEAF_NOT_FOUND' },
    )
    await assert.rejects(
      tree.refreshAgeLeaf('session-a', { leafIndex: 0, leafCommitment: H[0], birthDay: BIRTH_DAY - 400, expiryDay }, later),
      { code: 'AGE_LEAF_MISMATCH' },
      'a different birth day cannot be carried over',
    )
    await assert.rejects(
      tree.refreshAgeLeaf('session-a', { leafIndex: 1, leafCommitment: H[1], birthDay: BIRTH_DAY, expiryDay }, later),
      { code: 'AGE_LEAF_ENROLLMENT_INACTIVE' },
      'a revoked enrollment gets no fresh leaf',
    )

    const refreshed = await tree.refreshAgeLeaf('session-a', { leafIndex: 0, leafCommitment: H[0], birthDay: BIRTH_DAY, expiryDay }, later)
    assert.equal(refreshed.leafIndex, 4)
    assert.equal(refreshed.birthDay, BIRTH_DAY)
    assert.equal(refreshed.expiryDay, dayNumberOf(later) + tree.AGE_LEAF_TTL_DAYS)

    const { chunk, path } = await walletPath(4)
    assert.equal(chunk.leaves[0], '0', 'the replaced leaf leaves the tree')
    assert.equal(chunk.leaves[4], (await tree.computeAgeLeaf(H[0], BIRTH_DAY, refreshed.expiryDay)).toString())
    assert.ok(await tree.verifyAgeTreeMerklePath(chunk.leaves[4], path))

    await assert.rejects(
      tree.refreshAgeLeaf('session-a', { leafIndex: 0, leafCommitment: H[0], birthDay: BIRTH_DAY, expiryDay }, later),
      { code: 'AGE_LEAF_REPLACED' },
    )
  })

  it('builds paths across chunks: each chunk\'s wallets prove against the same root', async () => {
    // A leaf in chunk 1, placed directly so the test does not need 1500 enrollments.
    insertEnrollment('proof-far', 'session-b', inDays(365).toISOString())
    const expiryDay = today + tree.AGE_LEAF_TTL_DAYS
    const farLeaf = await tree.computeAgeLeaf(55n, BIRTH_DAY, expiryDay)
    getDb().prepare('INSERT INTO age_tree_leaves (leaf_index, leaf, proof_artifact_id, expiry_day) VALUES (1500, ?, ?, ?)')
      .run(farLeaf.toString(), 'proof-far', expiryDay)
    const root = (await tree.syncAgeTree({ force: true, now: NOW }))!
    assert.equal(root.size, 1501)

    const far = await walletPath(1500)
    assert.equal(far.chunk.chunk, 1)
    assert.equal(far.chunk.start, 1024)
    assert.equal(far.chunk.leaves[1500 - 1024], farLeaf.toString())
    assert.equal(far.path.root, root.root)
    assert.ok(await tree.verifyAgeTreeMerklePath(farLeaf.toString(), far.path))

    const near = await walletPath(4)
    assert.equal(near.path.root, root.root)
    assert.ok(await tree.verifyAgeTreeMerklePath(near.chunk.leaves[4], near.path))
    // The two paths meet: chunk 1's root is chunk 0's sibling at level 10.
    assert.equal(near.path.pathElements[tree.AGE_TREE_CHUNK_LEVEL], (await tree.ageTreeChunkRoots()).nodes[1])

    // A chunk from one version and chunk roots from another do not mix.
    await assert.rejects(
      tree.merklePathFromChunks(4, near.chunk.leaves.map((leaf, i) => (i === 4 ? '1' : leaf)), (await tree.ageTreeChunkRoots()).nodes),
      /different tree versions/,
    )
  })

  it('drops leaves from the tree once their expiry day has passed', async () => {
    const leafB = (await tree.ageTreeChunk(0)).leaves[2]
    assert.notEqual(leafB, '0')
    await tree.syncAgeTree({ force: true, now: inDays(tree.AGE_LEAF_TTL_DAYS + 1) })
    assert.equal((await tree.ageTreeChunk(0)).leaves[2], '0')
  })

  function dayNumberOf(date: Date) {
    const local = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Tijuana' }).format(date)
    return Math.round((Date.parse(`${local}T00:00:00Z`) - Date.UTC(1900, 0, 1)) / DAY)
  }
})
