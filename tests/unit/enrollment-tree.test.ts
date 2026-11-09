import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
// @ts-expect-error — no ESM types available for circomlibjs
import { buildPoseidon } from 'circomlibjs'
import {
  ENROLLMENT_TREE_CAPACITY,
  ENROLLMENT_TREE_DEPTH,
  buildEnrollmentTree,
  enrollmentPath,
} from '../../src/services/enrollmentTree.js'

/*
 * The tree must hash exactly as the circuit's MerkleTreeInclusion does
 * (zkp/circuits/lib/merkle.circom); the integration test proves against it.
 */

describe('enrollment tree', () => {
  it('builds zero subtrees as Poseidon(z, z)', async () => {
    const p = await buildPoseidon()
    const tree = await buildEnrollmentTree([])
    assert.equal(tree.zeros[0], '0')
    assert.equal(tree.zeros[1], p.F.toString(p([0n, 0n])))
    assert.equal(tree.root, tree.zeros[ENROLLMENT_TREE_DEPTH])
  })

  it('recomputes the root from any active leaf and its path', async () => {
    const p = await buildPoseidon()
    const leaves = ['11', '0', '33', '44', '55']
    const tree = await buildEnrollmentTree(leaves)
    for (const leaf of ['11', '33', '44', '55']) {
      const path = enrollmentPath(tree, leaf)!
      let node = BigInt(leaf)
      for (let k = 0; k < tree.depth; k += 1) {
        const sibling = BigInt(path.pathElements[k])
        node = p.F.toObject(path.pathIndices[k] === 0 ? p([node, sibling]) : p([sibling, node]))
      }
      assert.equal(node.toString(), tree.root, `root from leaf ${leaf}`)
    }
  })

  it('has no path for a zeroed (revoked) or unknown leaf', async () => {
    const tree = await buildEnrollmentTree(['11', '0'])
    assert.equal(enrollmentPath(tree, '0'), null)
    assert.equal(enrollmentPath(tree, '99'), null)
  })

  it('changes the root when a leaf is zeroed', async () => {
    const live = await buildEnrollmentTree(['11', '22'])
    const revoked = await buildEnrollmentTree(['11', '0'])
    assert.notEqual(live.root, revoked.root)
  })

  it('refuses more leaves than the tree holds', async () => {
    await assert.rejects(
      buildEnrollmentTree(new Array(ENROLLMENT_TREE_CAPACITY + 1).fill('1')),
      /full/,
    )
  })
})
