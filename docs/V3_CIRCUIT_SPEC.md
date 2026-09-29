# v3 circuit specification: `AgePresentationV3`

Status: **draft for audit.** Required by CD-15; design rationale in
`V3_UNLINKABLE_AGE_PROOFS.md`. Reference implementation:
`zkp/circuits/age_presentation_v3.circom` (+ `zkp/circuits/lib/merkle.circom`).
Executable checks: `node zkp/scripts/check-age-presentation-v3.mjs`.

## 1. Statement

The prover knows `(holderSecret, holderBlinding, birthDay, expiryDay, path)`
such that:

1. `leaf = Poseidon(1, Poseidon(holderSecret, holderBlinding), birthDay, expiryDay)`
   is in the issuer's v3 tree with root `root`;
2. `birthDay <= cutoffDay`;
3. `today <= expiryDay`;
4. `nym = 0` if `scope = 0`, else `nym = Poseidon(2, holderSecret, scope)`;

and the proof is bound to `challenge`.

## 2. Parameters

| Parameter | Value | Notes |
|---|---|---|
| Field | BN254 scalar field | Same as the existing circuits |
| Hash | circomlib Poseidon (t = 3, 4, 5) | Poseidon(2) for tree nodes and H; Poseidon(3) for nym; Poseidon(4) for the leaf |
| Tree | binary, depth `D = 20` (1,048,576 leaves) | Development builds may use a smaller depth |
| Empty leaf | `0` | `zeros[k+1] = Poseidon(zeros[k], zeros[k])` |
| Day encoding | whole days since 1900-01-01 UTC | 17 bits: 0 to 131,071, until the year 2258 |
| Domain tags | `LEAF_TAG = 1`, `NYM_TAG = 2` | Distinct arities also separate H (2 inputs) and tree nodes (2 inputs, never tagged) |
| Proof system | Groth16 | Ceremony in `ZK_CEREMONY_PLAN.md` |

## 3. Signals

Public signals, in snarkjs order: `root, nym, today, cutoffDay, challenge, scope`.

| Signal | Visibility | Constraint |
|---|---|---|
| `holderSecret` | private | Device-generated, uniform in the field, never leaves the wallet |
| `holderBlinding` | private | Random; makes H independent of any `nym` |
| `birthDay` | private | 17-bit range check; issuer-attested through the leaf |
| `expiryDay` | private | 17-bit range check; issuer-attested through the leaf |
| `pathElements[D]` | private | Siblings from the public tree |
| `pathIndices[D]` | private | Each constrained to be a bit |
| `today` | public | 17-bit range check |
| `cutoffDay` | public | 17-bit range check |
| `challenge` | public | Bound by `challenge * challenge` (used in no other constraint) |
| `scope` | public | 0, or a verifier-chosen scope id |
| `root` | output | MerkleTreeInclusion(leaf, path) |
| `nym` | output | `(1 - IsZero(scope)) * Poseidon(2, holderSecret, scope)` |

Constraint count (`--O2`): 4,300 at D = 14 and 5,758 at D = 20.

## 4. What the verifier must check outside the circuit

The circuit proves nothing without these:

1. **The Groth16 proof** verifies against the ceremony's verification key.
2. **`root`** is a root the issuer published and signed, and is either current
   or superseded less than `W` ago (revocation latency). Recommended
   `W = 24 h` for age checks.
3. **`today`** is the verifier's current UTC day, give or take 1 day for
   clock skew.
4. **`cutoffDay`** is exactly the last birth day that is at least N years
   before `today`, computed by the verifier on the calendar, so leap years stay
   outside the circuit. For a birthday on 29 February, N years later is taken
   as 1 March in non-leap years.
5. **`challenge`** equals `Poseidon(nonceField, audienceField)`:
   - `nonceField` is the verifier's single-use request nonce reduced into the
     field;
   - `audienceField` is SHA-256 of the audience identifier, truncated to
     248 bits;
   - the verifier marks the nonce used, which rejects replay.
6. **`scope`** is `0` unless the verifier needs one-per-person. Then it is the
   verifier's fixed scope id, and `nym` is checked for uniqueness within that
   scope.

## 5. Issuance

1. The wallet generates `holderSecret` and `holderBlinding` on the device and
   sends only `H = Poseidon(holderSecret, holderBlinding)`.
2. The issuer takes `birthDay` from the INE record it verified. It does not
   take it from the client (this closes THREAT_MODEL gap 8 for v3). It sets
   `expiryDay`.
3. The issuer appends the leaf, publishes the new root with an Ed25519
   signature under its issuer key, and returns `(birthDay, expiryDay,
   leafIndex)` to the wallet.
4. **Revocation** sets the leaf to 0 and publishes a new signed root. There is
   no revocation identifier anywhere in a proof.

## 6. Tree distribution

The wallet downloads the whole tree (or the populated levels, as
`GET /identity/enrollment-tree` does for CD-16) without authentication, and
computes its path locally. At D = 20 with many leaves, that means shipping
subtrees plus a Poseidon implementation in the wallet rather than every node.
The wallet must never request "the path for leaf i".

## 7. Transport

Proofs must reach the verifier without the holder's M8 session, through a
request token. Otherwise mubEZ links every proof to the account and the
cryptography buys nothing against it (CD-15).

## 8. Known limits

- **Soundness rests on the ceremony and on circomlib.** Poseidon parameters
  and the comparators, IsZero and Num2Bits templates.
- **Anonymity set.** Holders present at the chosen root, narrowed further by
  the choice of an older root.
- **Timing and network metadata** are outside the circuit.
- **A stolen `holderSecret`** lets the thief prove; the only remedy is
  revoking the leaf.

## 9. Questions for the audit

- Is `challenge * challenge` sufficient to bind the challenge (Groth16 public
  input malleability)?
- Are the 17-bit range checks complete for every comparator input, including
  the public ones?
- Is `nym = (1 - IsZero(scope)) * hash` sound (can a prover output `nym = 0`
  with a non-zero scope)?
- Is domain separation between H, nodes, leaves and nym adequate given shared
  Poseidon arities?
- Does `MerkleTreeInclusion` accept anything other than a bit for
  `pathIndices`, or a wrong-length path?
- Off-circuit: the root policy, the `cutoffDay` computation, the challenge
  derivation, nonce single use, and the tree construction in
  `enrollmentTree.ts`.
