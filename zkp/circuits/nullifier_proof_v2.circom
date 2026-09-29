pragma circom 2.1.6;

include "../circomlib/circuits/poseidon.circom";
include "../circomlib/circuits/comparators.circom";
include "../circomlib/circuits/bitify.circom";
include "./lib/merkle.circom";

/**
 * NullifierProofV2(depth)  (CD-16)
 *
 * Proves, without revealing which enrollment:
 *   1. commitment = Poseidon(birthYear, salt) is a leaf of the issuer's
 *      enrollment tree with the public `root`;
 *   2. nullifier = Poseidon(salt, communityId), one per enrollment and
 *      community;
 *   3. birthYear <= currentYear - ageThreshold, with birthYear range-checked
 *      to 16 bits so the comparator cannot be satisfied by a wrapped field
 *      element.
 *
 * v1 published `commitment`, one stable value shared by every community an
 * enrollment joined, and matched it to the enrollment artifact. v2 publishes
 * only `root`, which is the same for every enrolled person at a given time.
 *
 * Public signals (snarkjs order): root, nullifier, communityId, currentYear,
 * ageThreshold.
 */
template NullifierProofV2(depth) {
    // Private witness
    signal input birthYear;
    signal input salt;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    // Public inputs
    signal input communityId;
    signal input currentYear;
    signal input ageThreshold;

    // Public outputs
    signal output root;
    signal output nullifier;

    component birthYearBits = Num2Bits(16);
    birthYearBits.in <== birthYear;

    component commitment = Poseidon(2);
    commitment.inputs[0] <== birthYear;
    commitment.inputs[1] <== salt;

    component tree = MerkleTreeInclusion(depth);
    tree.leaf <== commitment.out;
    for (var i = 0; i < depth; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }
    root <== tree.root;

    component nullifierHash = Poseidon(2);
    nullifierHash.inputs[0] <== salt;
    nullifierHash.inputs[1] <== communityId;
    nullifier <== nullifierHash.out;

    component le = LessEqThan(16);
    le.in[0] <== birthYear;
    le.in[1] <== currentYear - ageThreshold;
    le.out === 1;
}

component main { public [communityId, currentYear, ageThreshold] } = NullifierProofV2(14);
