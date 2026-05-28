pragma circom 2.1.6;

include "../circomlib/circuits/poseidon.circom";
include "../circomlib/circuits/comparators.circom";

/**
 * IneAgeProof
 *
 * Demonstrates that the prover knows a birthYear and salt such that:
 *   1. commitment = Poseidon(birthYear, salt)
 *   2. birthYear <= currentYear - ageThreshold
 *
 * This proves "I am at least ageThreshold years old" without revealing
 * the exact birth year.
 *
 * Public outputs:
 *   - commitment: Poseidon hash binding birthYear to salt
 *
 * Public inputs:
 *   - currentYear: the year against which age is evaluated
 *   - ageThreshold: minimum age required (e.g., 18)
 *
 * Private inputs (witness):
 *   - birthYear: the prover's year of birth
 *   - salt: random salt preventing brute-force commitment reversal
 */
template IneAgeProof() {
    // Private witness
    signal input birthYear;
    signal input salt;

    // Public inputs
    signal input currentYear;
    signal input ageThreshold;

    // Public output
    signal output commitment;

    // ─── 1. Compute commitment = Poseidon(birthYear, salt) ────────────────
    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== birthYear;
    poseidon.inputs[1] <== salt;
    commitment <== poseidon.out;

    // ─── 2. Verify age: birthYear <= currentYear - ageThreshold ───────────
    // maxBirthYear is the latest birth year that still satisfies the threshold
    signal maxBirthYear <== currentYear - ageThreshold;

    // LessEqThan(16) works for values up to 2^16 - 1 (65535), sufficient for years
    component le = LessEqThan(16);
    le.in[0] <== birthYear;
    le.in[1] <== maxBirthYear;
    le.out === 1;
}

component main { public [currentYear, ageThreshold] } = IneAgeProof();
