import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'
import { issueIneCredentialWithClientProof } from '../helpers/clientProof.js'

/*
 * Nullifier proofs v2 (CD-16): membership in the issuer's enrollment tree,
 * one nullifier per enrollment and community, and nothing that identifies the
 * enrollment. v1 published the commitment, which linked every community an
 * enrollment joined and led back to its INE artifact.
 */

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-nullifier-test-'))
process.env.DATABASE_PATH = join(tmpDir, 'nullifier-test.db')
// Several enrollments in one minute; the auth-category limit is not under test.
process.env.RATE_LIMIT_AUTH_MAX = '1000'

type Tree = import('../../src/services/enrollmentTree.js').EnrollmentTree

describe('Nullifier ZKP v2 integration', () => {
  let app: TestApp
  let accessToken: string
  let zkp: typeof import('../../src/services/zkpService.js')
  let trees: typeof import('../../src/services/enrollmentTree.js')
  let getDb: typeof import('../../src/db/connection.js').getDb
  const year = new Date().getUTCFullYear()

  const auth = () => ({ authorization: `Bearer ${accessToken}` })

  async function enroll(photo: string) {
    const issued = await issueIneCredentialWithClientProof({
      app, accessToken, inePhotoBase64: photo, selfieBase64: `${photo}-selfie`,
    })
    assert.equal(issued.response.statusCode, 200, issued.response.payload)
    return {
      witness: issued.clientProof.witness,
      commitment: issued.body.commitment as string,
      proofArtifactId: issued.body.proofArtifactId as string,
    }
  }

  async function fetchTree(): Promise<Tree> {
    const res = await app.inject({ method: 'GET', url: '/v1/identity/enrollment-tree' })
    assert.equal(res.statusCode, 200)
    return JSON.parse(res.payload)
  }

  async function prove(
    enrollment: Awaited<ReturnType<typeof enroll>>,
    tree: Tree,
    communityId: number,
    overrides: { currentYear?: number; ageThreshold?: number } = {},
  ) {
    const path = trees.enrollmentPath(tree, enrollment.commitment)
    assert.ok(path, 'enrollment is an active leaf of this tree')
    return zkp.generateNullifierProof({
      birthYear: enrollment.witness.birthYear,
      salt: enrollment.witness.salt,
      communityId,
      currentYear: overrides.currentYear ?? year,
      ageThreshold: overrides.ageThreshold ?? 18,
      pathElements: path.pathElements,
      pathIndices: path.pathIndices,
    })
  }

  async function submit(proof: { proof: unknown; publicSignals: string[] }, communityId: string) {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/identity/ine/zkp-nullifier',
      headers: auth(),
      payload: { proof: proof.proof, publicSignals: proof.publicSignals, communityId },
    })
    return { status: res.statusCode, body: JSON.parse(res.payload) }
  }

  before(async () => {
    const { buildApp } = await import('../../src/index.js')
    zkp = await import('../../src/services/zkpService.js')
    trees = await import('../../src/services/enrollmentTree.js')
    ;({ getDb } = await import('../../src/db/connection.js'))
    app = await buildApp()
    const start = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'nullifieruser.bsky.social' },
    })
    accessToken = JSON.parse(start.payload).tokens.accessToken
  })

  after(async () => {
    await app.close()
  })

  it('serves the enrollment tree without authentication', async () => {
    const enrollment = await enroll('mock-nullifier-tree')
    const tree = await fetchTree()
    assert.equal(tree.depth, trees.ENROLLMENT_TREE_DEPTH)
    assert.ok(tree.levels[0].includes(enrollment.commitment))
    assert.equal(tree.zeros.length, tree.depth + 1)
  })

  it('accepts a membership proof and stores no commitment and no session', async () => {
    const enrollment = await enroll('mock-nullifier-valid')
    const proof = await prove(enrollment, await fetchTree(), 42)
    assert.ok(!proof.publicSignals.includes(enrollment.commitment), 'the proof does not reveal the commitment')

    const result = await submit(proof, '42')
    assert.equal(result.status, 200, JSON.stringify(result.body))
    assert.deepEqual(result.body, { valid: true, nullifier: proof.nullifier })

    const columns = (getDb().prepare('PRAGMA table_info(nullifiers)').all() as Array<{ name: string }>).map((c) => c.name)
    assert.deepEqual(columns.sort(), ['community_id', 'created_at', 'id', 'nullifier'])
    const row = getDb().prepare('SELECT * FROM nullifiers WHERE nullifier = ?').get(proof.nullifier) as Record<string, unknown>
    assert.equal(row.community_id, '42')
  })

  it('rejects a reused nullifier for the same community', async () => {
    const enrollment = await enroll('mock-nullifier-reuse')
    const tree = await fetchTree()
    assert.equal((await submit(await prove(enrollment, tree, 7), '7')).status, 200)

    const again = await submit(await prove(enrollment, tree, 7), '7')
    assert.equal(again.status, 400)
    assert.equal(again.body.reason, 'nullifier_already_used')
  })

  it('publishes nothing that links one enrollment across communities', async () => {
    const alice = await enroll('mock-nullifier-alice')
    const bob = await enroll('mock-nullifier-bob')
    const tree = await fetchTree()

    const aliceA = await prove(alice, tree, 100)
    const aliceB = await prove(alice, tree, 200)
    const bobA = await prove(bob, tree, 101)

    // Alice's two proofs share only what every enrolled person shares.
    const shared = aliceA.publicSignals.filter((signal) => aliceB.publicSignals.includes(signal))
    assert.deepEqual(shared.sort(), [aliceA.root, String(year), '18'].sort())
    assert.notEqual(aliceA.nullifier, aliceB.nullifier)
    // The root is the same for Bob: it does not single out Alice.
    assert.equal(bobA.root, aliceA.root)
  })

  it('rejects a mismatched community', async () => {
    const enrollment = await enroll('mock-nullifier-mismatch')
    const result = await submit(await prove(enrollment, await fetchTree(), 99), '100')
    assert.equal(result.status, 400)
    assert.equal(result.body.reason, 'community_mismatch')
  })

  it('rejects a root the issuer never published', async () => {
    const enrollment = await enroll('mock-nullifier-fake-root')
    // A tree of the prover's own making, holding only their commitment.
    const fake = await trees.buildEnrollmentTree([enrollment.commitment])
    const result = await submit(await prove(enrollment, fake, 55), '55')
    assert.equal(result.status, 400)
    assert.equal(result.body.reason, 'unknown_or_stale_root')
  })

  it('rejects a wrong year and an out-of-range age threshold', async () => {
    const enrollment = await enroll('mock-nullifier-policy')
    const tree = await fetchTree()

    const lastYear = await submit(await prove(enrollment, tree, 61, { currentYear: year - 1 }), '61')
    assert.equal(lastYear.body.reason, 'current_year_mismatch')

    const noThreshold = await submit(await prove(enrollment, tree, 62, { ageThreshold: 0 }), '62')
    assert.equal(noThreshold.body.reason, 'age_threshold_out_of_range')
  })

  it('drops a revoked enrollment from the tree, after the grace window', async () => {
    const enrollment = await enroll('mock-nullifier-revoked')
    const before = await fetchTree()
    assert.ok(trees.enrollmentPath(before, enrollment.commitment))

    const revoke = await app.inject({
      method: 'POST', url: '/v1/identity/revoke', headers: auth(),
      payload: { proofArtifactId: enrollment.proofArtifactId },
    })
    assert.equal(revoke.statusCode, 200)

    const afterRevoke = await fetchTree()
    assert.notEqual(afterRevoke.root, before.root)
    assert.equal(trees.enrollmentPath(afterRevoke, enrollment.commitment), null, 'the leaf is now zero')

    // A proof against the previous root is still accepted inside the window...
    assert.equal((await submit(await prove(enrollment, before, 71), '71')).status, 200)

    // ...and refused once the window has passed.
    getDb()
      .prepare('UPDATE enrollment_roots SET superseded_at = ? WHERE root = ?')
      .run(new Date(Date.now() - (trees.ENROLLMENT_ROOT_GRACE_SEC + 60) * 1000).toISOString(), before.root)
    const stale = await submit(await prove(enrollment, before, 72), '72')
    assert.equal(stale.status, 400)
    assert.equal(stale.body.reason, 'unknown_or_stale_root')
  })
})
