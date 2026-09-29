pragma circom 2.1.6;

include "../circomlib/circuits/poseidon.circom";
include "../circomlib/circuits/comparators.circom";
include "../circomlib/circuits/bitify.circom";
include "./lib/merkle.circom";

/**
 * AgePresentationV3(depth)  --  DRAFT for audit (docs/V3_CIRCUIT_SPEC.md)
 *
 * Proves "born on or before cutoffDay, credential valid on `today`" for a
 * credential the issuer placed in its v3 tree, bound to one request, without
 * revealing anything that identifies the holder or links two proofs.
 *
 *   H    = Poseidon(holderSecret, holderBlinding)        holder commitment
 *   leaf = Poseidon(LEAF_TAG, H, birthDay, expiryDay)     issuer-attested leaf
 *   MerkleTreeInclusion(leaf, path) == root               issuer binding
 *   birthDay  <= cutoffDay                                age statement
 *   today     <= expiryDay                                not expired
 *   nym = scope != 0 ? Poseidon(NYM_TAG, holderSecret, scope) : 0
 *
 * Days are counted from 1900-01-01 (UTC) and range-checked to 17 bits, so no
 * comparator can be satisfied by a wrapped field element. `challenge` is
 * computed by the verifier from its request and only bound here.
 *
 * Public signals (snarkjs order): root, nym, today, cutoffDay, challenge, scope.
 */

template AgePresentationV3(depth) {
    var LEAF_TAG = 1;
    var NYM_TAG = 2;

    // Private witness
    signal input holderSecret;
    signal input holderBlinding;
    signal input birthDay;
    signal input expiryDay;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    // Public inputs
    signal input today;
    signal input cutoffDay;
    signal input challenge;
    signal input scope;

    // Public outputs
    signal output root;
    signal output nym;

    // Range checks: every comparator input fits 17 bits.
    component birthBits = Num2Bits(17);
    birthBits.in <== birthDay;
    component expiryBits = Num2Bits(17);
    expiryBits.in <== expiryDay;
    component todayBits = Num2Bits(17);
    todayBits.in <== today;
    component cutoffBits = Num2Bits(17);
    cutoffBits.in <== cutoffDay;

    // Holder commitment and issuer-attested leaf.
    component holder = Poseidon(2);
    holder.inputs[0] <== holderSecret;
    holder.inputs[1] <== holderBlinding;

    component leaf = Poseidon(4);
    leaf.inputs[0] <== LEAF_TAG;
    leaf.inputs[1] <== holder.out;
    leaf.inputs[2] <== birthDay;
    leaf.inputs[3] <== expiryDay;

    component tree = MerkleTreeInclusion(depth);
    tree.leaf <== leaf.out;
    for (var i = 0; i < depth; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }
    root <== tree.root;

    // Age statement and validity.
    component oldEnough = LessEqThan(17);
    oldEnough.in[0] <== birthDay;
    oldEnough.in[1] <== cutoffDay;
    oldEnough.out === 1;

    component notExpired = LessEqThan(17);
    notExpired.in[0] <== today;
    notExpired.in[1] <== expiryDay;
    notExpired.out === 1;

    // Scoped pseudonym, zero when the verifier asks for none, so proofs
    // without a scope share no per-holder value.
    component scopeIsZero = IsZero();
    scopeIsZero.in <== scope;
    component nymHash = Poseidon(3);
    nymHash.inputs[0] <== NYM_TAG;
    nymHash.inputs[1] <== holderSecret;
    nymHash.inputs[2] <== scope;
    nym <== (1 - scopeIsZero.out) * nymHash.out;

    // Bind the request challenge into the proof (it takes part in no other
    // constraint); squaring keeps the compiler from dropping it.
    signal challengeSquare;
    challengeSquare <== challenge * challenge;
}

component main { public [today, cutoffDay, challenge, scope] } = AgePresentationV3(20);
