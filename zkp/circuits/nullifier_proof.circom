pragma circom 2.1.6;

include "../circomlib/circuits/poseidon.circom";
include "../circomlib/circuits/comparators.circom";

/**
 * NullifierProof
 *
 * Demonstrates that the prover knows a birthYear, salt, and communityId such that:
 *   1. commitment = Poseidon(birthYear, salt)
 *   2. nullifier = Poseidon(salt, communityId)
 *   3. birthYear <= currentYear - ageThreshold
 *
 * This proves "I am the same verified citizen who committed to birthYear,
 * and I want to join this specific community, and this is my unique
 * nullifier for this community" — all without revealing birthYear or salt.
 *
 * Public outputs:
 *   - commitment: Poseidon hash binding birthYear to salt
 *   - nullifier: Poseidon hash binding salt to communityId
 *
 * Public inputs:
 *   - communityId: the community the user wants to join
 *   - currentYear: the year against which age is evaluated
 *   - ageThreshold: minimum age required
 *
 * Private inputs (witness):
 *   - birthYear: the prover's year of birth
 *   - salt: random salt from the INE credential
 */
template NullifierProof() {
    // Private witness
    signal input birthYear;
    signal input salt;

    // Public inputs
    signal input communityId;
    signal input currentYear;
    signal input ageThreshold;

    // Public outputs
    signal output commitment;
    signal output nullifier;

    // ─── 1. commitment = Poseidon(birthYear, salt) ────────────────────────
    component poseidonCommitment = Poseidon(2);
    poseidonCommitment.inputs[0] <== birthYear;
    poseidonCommitment.inputs[1] <== salt;
    commitment <== poseidonCommitment.out;

    // ─── 2. nullifier = Poseidon(salt, communityId) ───────────────────────
    component poseidonNullifier = Poseidon(2);
    poseidonNullifier.inputs[0] <== salt;
    poseidonNullifier.inputs[1] <== communityId;
    nullifier <== poseidonNullifier.out;

    // ─── 3. Verify age: birthYear <= currentYear - ageThreshold ───────────
    signal maxBirthYear <== currentYear - ageThreshold;

    component le = LessEqThan(16);
    le.in[0] <== birthYear;
    le.in[1] <== maxBirthYear;
    le.out === 1;
}

component main { public [communityId, currentYear, ageThreshold] } = NullifierProof();
