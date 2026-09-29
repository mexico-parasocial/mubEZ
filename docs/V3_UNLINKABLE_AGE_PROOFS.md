# Proposal: unlinkable age proofs (`m8.identity.presentation.v3`)

Status: **required (CD-15), not built.** Age checks must leave no trace, so v3
is the release path for statements like "at least 18". v2 stays only for
requests whose purpose is to identify (`curp_hash`, `district_hash`), which
are linkable by nature.

## Goal

A holder proves "at least *N* years old today" to a verifier such that:

1. **Issuer-bound:** only a birth date the issuer attested can satisfy it.
2. **Holder-bound:** only the device holding the holder secret can produce it.
3. **Request-bound:** a proof answers one request and cannot be replayed.
4. **Unlinkable:** two proofs by the same holder, to the same or different
   verifiers, share no value that identifies the holder. The issuer cannot link
   a proof to an issuance either.
5. **Revocable without a reusable public identifier:** revoking stops future
   proofs, and nothing in a proof identifies which credential it came from.
6. Reveals nothing but the statement: no DID, no citizenship, no 21+ status.

## Can it build on the existing ZK work?

**On the stack, yes; on the circuits, no.**

Reusable:
- circom + the vendored circomlib (Poseidon, comparators, Merkle/SMT helpers,
  EdDSA-Poseidon);
- snarkjs verification in `zkpService`;
- the WebView prover pipeline (`zkp/prover/prover.html`, wasm/zkey served by
  mubEZ, the artifact manifest and attestation).

Not reusable as-is:
- `ine_age_proof` is **not issuer-bound**. `birthYear` is a free witness the
  client chooses; the issuer never signs or checks the commitment, and
  `/identity/ine/credential` does not compare it with the INE birth date.
  Today it proves only that *some* year satisfies the threshold.
- Both circuits **publish `commitment`**, a stable identifier. `nullifier_proof`
  outputs it next to the per-community nullifier, and mubEZ stores
  `(nullifier, community_id, commitment, session_id)`. Community memberships
  are therefore linkable to each other and to the session.
- **Year granularity:** the check is `birthYear <= currentYear - threshold`,
  wrong by up to a year.
- **Single-party trusted setup:** the Groth16 phase 2 was run by one party
  (`zkp/scripts/setup.sh`), who could forge proofs.

## Design

The holder keeps a secret `s` (random 254-bit field element, device-only,
user-presence gated like the v2 holder key; never derived from the recovery
phrase).

**Issuance.**
1. The wallet sends `H = Poseidon(s, r)` for a random `r`.
2. The issuer, which knows the birth date from the INE record, computes
   `leaf = Poseidon(H, birthDay, expiryDay)` (days since epoch).
3. It appends the leaf to an issuer-maintained Poseidon Merkle tree (depth
   around 20) and publishes the new root, signed with the issuer key.
4. The wallet stores `s, r, birthDay, expiryDay, leafIndex` and the Merkle
   path.

The issuer binding is membership in the issuer's tree. This is the Semaphore
group pattern: no in-circuit signature is needed, and revocation comes with it.

**Presentation circuit** (`AgePresentationV3`):

| | |
|---|---|
| Private | `s, r, birthDay, expiryDay, pathElements, pathIndices` |
| Public | `root, today, cutoffDay, challenge` (and optionally `scope`) |

Constraints:
- `H = Poseidon(s, r)`; `leaf = Poseidon(H, birthDay, expiryDay)`;
  `MerkleProof(leaf, path) == root` — issuer binding, holder binding.
- `birthDay <= cutoffDay`, where the verifier computes `cutoffDay` (the last
  birth day that is at least *N* years before `today`) outside the circuit,
  which keeps leap years out of it.
- `today <= expiryDay`.
- `challenge = Poseidon(requestNonce, audienceHash)` is a public input the
  proof is bound to; no output depends on `s` except as below.
- Optional scoped pseudonym, output only when a verifier needs
  one-per-person: `nym = Poseidon(s, scope)`. It is stable within a scope and
  unlinkable across scopes. It must never be `commitment` or `H`.

**Verification.** The verifier checks:
- the Groth16 (or PLONK) proof;
- `root` is one of the issuer's signed roots from the last *W* hours;
- `today` is the current day and `cutoffDay` matches it for the threshold;
- `challenge` matches its request, which it marks used.

**Revocation.** Revoking an enrollment sets its leaf to zero and publishes a
new root; proofs against roots older than *W* are refused, so revocation takes
effect within *W*. Nothing about the revoked leaf is published beyond the tree
itself, whose leaves are hiding commitments. Short-lived leaves (`expiryDay`
of a few weeks, re-issued on request) bound the window further and keep old
leaves from piling up.

**Witness updates.** When the tree changes, holders need fresh paths.
Fetching "my path for index *i*" tells the server *i*. So the wallet downloads
tree frontiers or whole subtrees rather than its own path, and accepts that the
issuer learns *when* a holder refreshes, not what it proves.

## What remains linkable

- **Network metadata and timing.** The relying party sees the client's IP
  unless presentations go through a relay.
- **The root chosen.** Wallets should always prove against the latest root;
  an old root narrows the anonymity set to holders present at that time.
- **`today`, `cutoffDay` (the threshold), and `nym` within its scope,** by design.
- **The session, if presentations keep flowing through the holder's M8
  session.** v3 needs a transport where the relying party (or an
  unauthenticated mubEZ verification endpoint) receives the proof without
  learning the account: a request token instead of the session mailbox. Without
  that change, mubEZ links every v3 proof to the account exactly as in v2, and
  the cryptography buys nothing against mubEZ.

## Migration

1. **Build.** New circuit, a multi-party phase-2 ceremony (or PLONK with a
   universal setup, which snarkjs supports), and a circuit audit.
2. **Issuer.** Issuer tree and signed-root publication; revocation by leaf
   zeroing; `/identity/ine/credential` adds a leaf alongside v2 issuance, the
   birth date taken from the INE record rather than a client witness.
3. **Wallet.** The iM8 wallet stores `s` and paths; the prover WebView gains
   the v3 circuit.
4. **Transport.** A token-addressed request/response route for v3
   presentations.
5. **Verifiers** accept v3 for threshold statements and keep v2 only for
   identifier requests. Existing v2 credentials keep working until expiry;
   enrollments get a leaf on their next re-issuance.
6. **Retire** the `commitment` output of `nullifier_proof` (or its public use)
   and the commitment column in `nullifiers`, replacing it with scoped `nym`s.

## Risks

- Circuit bugs are soundness bugs; audit before any gate opens.
- Mobile proving time: a depth-20 Merkle proof is a few thousand constraints,
  well within WebView proving, but it must be measured on target devices.
- Tree availability and root distribution become part of the trust base.
- A stolen `s` has the same custody problem as the v2 holder key; there is no
  hardware support for Poseidon or Baby Jubjub keys.
