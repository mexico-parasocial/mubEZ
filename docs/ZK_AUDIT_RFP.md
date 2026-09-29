# Request for proposal: ZK circuit and verifier audit

Draft to send to audit firms. Status: **not sent.**

## Project

Mexico Parasocial runs PARA (a civic social app on the AT Protocol), iM8 (the
identity wallet) and mubEZ (the issuer and verifier backend). Citizens enrol
once with their INE voter ID and can then prove facts such as "18 or older",
or join a community once per person, **without leaving a trace**: no verifier,
including our own backend, may learn the account or link two proofs (product
requirement CD-15).

## Scope

### Circuits (circom 2.1.6, Groth16 over BN254, circomlib)

| File | Purpose | Constraints (`--O2`, depth 20) |
|---|---|---|
| `zkp/circuits/lib/merkle.circom` | Poseidon(2) binary Merkle inclusion | shared |
| `zkp/circuits/nullifier_proof_v2.circom` | Enrollment-tree membership + per-community nullifier + age threshold | 5,372 |
| `zkp/circuits/age_presentation_v3.circom` | Issuer-bound, unlinkable age proof with optional scoped pseudonym | 5,758 |

### Off-circuit code the soundness depends on (TypeScript)

- `src/services/enrollmentTree.ts`: tree construction, leaf activation from
  revocation state, and the root acceptance window.
- `app/controllers/zk_proof_controller.ts`: public-input validation (year,
  threshold, community, root) and nullifier uniqueness.
- `zkp/prover/prover.html`: client-side proving page. Note that it loads
  snarkjs from a CDN without subresource integrity.
- The v3 verifier obligations in `docs/V3_CIRCUIT_SPEC.md` §4. The v3 verifier
  is not implemented yet; we ask for a design review of it.

### Documents

- `docs/V3_CIRCUIT_SPEC.md` (statement, signals, verifier checks, questions)
- `docs/CRYPTO_DECISIONS.md` CD-13 to CD-16
- `docs/WALLET_PRIVACY.md`
- `THREAT_MODEL.md`

## What we want to know

1. **Soundness.** Can a prover without an active enrollment, or with an age
   below the threshold, produce an accepted proof? Are any constraints under-
   or over-specified? Are the range checks complete?
2. **Unlinkability.** Does any public signal, or any verifier-side behaviour,
   link two proofs by the same holder, or a proof to an enrollment?
3. **Nullifier and pseudonym uniqueness.** Can one enrollment obtain two
   accepted nullifiers for a community, or two `nym`s for a scope?
4. **Binding.** Are `challenge` and `scope` bound (Groth16 malleability)?
5. **Specific questions** in `V3_CIRCUIT_SPEC.md` §9.
6. **Ceremony plan review** (`ZK_CEREMONY_PLAN.md`): phase 1 choice and
   phase 2 procedure.

## Out of scope

- The AT Protocol client (PARA UI), the wallet's key storage, and the v2
  Ed25519 presentation format.
- These may be quoted separately if you offer it.

## Deliverables

- A written report with severity-rated findings and proof-of-concept witnesses
  where applicable.
- A re-review of our fixes.
- Optional: participation as a contributor in the phase 2 ceremony, which
  starts after the fixes are frozen.

## Timeline and logistics

- Code is frozen at a commit we will name at kickoff.
- Please include the following in your proposal:
  - earliest start date;
  - estimated effort and calendar duration;
  - price;
  - your experience with circom and Groth16 audits, with public reports if
    available;
  - whether you use formal or automated tooling for circom (for example
    under-constrained-signal detection).

## Candidate firms

These firms are known for ZK or circom audits. Their availability and current
offering have not been checked; confirm both before sending.

- Veridise
- zkSecurity
- Trail of Bits
- Zellic
- Least Authority
- Nethermind Security
- Hexens

Ask at least three for proposals, and compare them on circom-specific
experience before price.

Contact: _<name, email>_
