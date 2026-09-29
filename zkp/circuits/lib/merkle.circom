pragma circom 2.1.6;

include "../../circomlib/circuits/poseidon.circom";

/**
 * MerkleTreeInclusion(depth)
 *
 * Recomputes the root of a binary Poseidon(2) Merkle tree from a leaf and its
 * authentication path. pathIndices[i] is 0 when the running node is the left
 * child at level i and 1 when it is the right child; it is constrained to be
 * a bit. Empty positions hold zero subtrees: zeros[0] = 0 and
 * zeros[k+1] = Poseidon(zeros[k], zeros[k]), matching the issuer's tree in
 * src/services/enrollmentTree.ts.
 *
 * Shared by nullifier_proof_v2 and the v3 age presentation.
 */
template MerkleTreeInclusion(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal output root;

    signal levels[depth + 1];
    signal left[depth];
    signal right[depth];
    component hashers[depth];

    levels[0] <== leaf;
    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        // index 0: (node, sibling); index 1: (sibling, node)
        left[i] <== levels[i] + pathIndices[i] * (pathElements[i] - levels[i]);
        right[i] <== pathElements[i] + pathIndices[i] * (levels[i] - pathElements[i]);

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== left[i];
        hashers[i].inputs[1] <== right[i];
        levels[i + 1] <== hashers[i].out;
    }
    root <== levels[depth];
}
