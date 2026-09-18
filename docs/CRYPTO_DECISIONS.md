# Cryptographic Decisions

Decisions taken, with the alternatives rejected and why. Append new entries;
do not rewrite old ones. If a decision is reversed, add a new entry that
supersedes it by number and say so in both.

---

## CD-1 — Peppered HMAC for CURP and district hashes

**Decision.** `curp_hash` and `district_hash` are
`HMAC-SHA256(pepper, domain ‖ normalized_input)`, full 32-byte digest, encoded
as `hmac-sha256:<keyId>:<hex>`. The pepper is server-side secret material
behind `PepperProvider` (`src/services/curpHash.ts`).

**Problem.** The previous scheme was `sha256(curp)` truncated to 16 hex chars.
A CURP is structured, low-entropy data (name initials, birth date, sex, state,
checksum): the plausible space is small enough to enumerate offline. Anyone
who exfiltrated the database could brute-force every hash back to a real
person. Truncation to 64 bits made collisions plausible on top of that.

**Rejected alternatives.**

- *Per-row random salt.* Breaks the point: these hashes must be deterministic
  so an identity can be matched and deduped across issuances.
- *Argon2/scrypt on the CURP.* Slows an attacker but does not stop them: the
  input space is small enough that even an expensive KDF is enumerable given
  the hashes. A secret the attacker does not have is the property we need, not
  a cost factor.
- *Encrypting the CURP instead of hashing.* Creates a decryptable store of
  national identifiers — strictly worse under the insider-threat model.
- *Keeping truncation.* No benefit; storage was never the constraint.

**Consequences.** Losing the pepper makes existing hashes unverifiable — it is
a durable secret with the same handling requirements as the issuer key. Key
ids are embedded in the hash so a pepper can be rotated with a grace period
(`CURP_PEPPER_PREVIOUS`). Legacy `sha256:` hashes still verify and are flagged
`legacy: true` for re-issuance; they remain brute-forceable until re-issued,
which is recorded as residual risk in `THREAT_MODEL.md`.

**Supersedes.** The inline hashing formerly in `app/controllers/ine_controller.ts`.

---

## CD-2 — ristretto255 for identity derivation

**Decision.** Identity keys are derived on ristretto255 per
`docs/IDENTITY_DERIVATION.md`, using `@noble/curves`.

**Rejected alternatives.**

- *Raw Ed25519 / Curve25519 points.* The cofactor-8 subgroup is a persistent
  source of implementation bugs, and ring signatures and Pedersen commitments
  (planned) need a prime-order group. ristretto255 gives that without
  cofactor clearing at every call site.
- *secp256k1.* No advantage here, and worse library support for the
  ristretto-style constructions this roadmap needs.
- *BN254 (already in the repo for Groth16).* Pairing-friendly curves are
  slower for plain signatures and are being retired from the vote path
  anyway.

**Consequences.** One curve serves derivation, the planned CLSAG-style ring
signatures, and Pedersen commitments for blind delegation. `@noble/curves`
runs on both Node and React Native/Hermes, so client and server share one
implementation family and one set of test vectors.

---

## CD-3 — SHA-512 little-endian as hash-to-scalar

**Decision.** `H_s(x) = LE(SHA-512(x)) mod l`.

**Rejected alternatives.**

- *SHA-256 reduced mod l.* 256 bits reduced mod a ~253-bit order leaves
  measurable modulo bias. 512 bits makes the bias negligible.
- *Big-endian interpretation.* Little-endian matches the curve25519/Monero
  convention and the encoding of scalars everywhere else in this system;
  mixing endianness is a classic interop bug.
- *hash_to_field / hash-to-curve (RFC 9380).* Correct and rigorous, but
  heavier than needed for deriving a scalar tweak, and adds an implementation
  the client must match exactly.

**Consequences.** Domain-separation labels are mandatory and versioned
(`m8/derive/spend/v1`, `para-id/v1`) so the same seed never produces the same
scalar in two contexts.

---

## CD-4 — Additive (Monero subaddress style) identity derivation

**Decision.** `identity_pub_i = spend_pub + H_s(label ‖ view_priv ‖ i)·G`.

**Rejected alternatives.**

- *Independent random keys per identity.* Three separate secrets to back up,
  and no way to later prove common ownership when the user wants to.
- *BIP-32/SLIP-0010 hardened derivation.* Standard and well-tooled, but
  hardened derivation gives no view-key capability: nobody can recompute the
  public keys without the master secret. The view key is what enables future
  selective disclosure, audit, and recovery flows without signing power.
- *Deriving identities from the CURP or any server-known value.* Would let the
  server recompute and link every identity — the exact property being removed.

**Consequences.** One 32-byte seed is the single backup artifact. A holder of
(`spend_pub`, `view_priv`) can recompute identity public keys but cannot sign.
Seed compromise is total by construction, which is why the seed lives only in
hardware-backed storage plus its mnemonic backup.

---

## CD-5 — The seed is the BIP-39 entropy (no passphrase stretching)

**Decision.** The 32-byte seed is used directly as BIP-39 entropy, producing a
24-word mnemonic that round-trips to exactly those bytes. No PBKDF2
`mnemonicToSeed` step.

**Rejected alternatives.**

- *Standard BIP-39 `mnemonicToSeed` (PBKDF2, 2048 rounds, 64-byte output).*
  Designed to stretch a possibly-weak user passphrase. Our seed is already
  32 bytes of CSPRNG output, so stretching adds no entropy — it only adds a
  step where client and server implementations can silently disagree.
- *Custom wordlist.* No benefit; loses existing BIP-39 tooling, wallet
  interop, and the user-facing familiarity of 24 words.

**Consequences.** Mnemonic ↔ seed is a pure, testable bijection covered by the
shared vectors. A 12-word mnemonic (16 bytes) is explicitly rejected at input:
valid BIP-39, wrong size for this system.

---

## CD-6 — Signing behind an async `IssuerSigner`, never a key handout

**Decision.** Issuer signing goes through
`IssuerSigner.sign(payload): Promise<Uint8Array>`. Private key material never
crosses the interface. Verification keys live in a separate `IssuerKeyStore`.

**Problem.** The previous `IssuerKeyStore.getSigningKey()` was synchronous and
returned the private `KeyObject`. No KMS can implement that: a KMS performs the
signature and never releases the key. The documented "KMS migration path" was
therefore not implementable as written.

**Rejected alternatives.**

- *Keeping the sync interface and having the KMS adapter fetch/cache the
  private key.* Defeats the entire purpose of using a KMS.
- *One combined interface for signing and verification.* Verification is
  synchronous, frequent, and needs only public data; signing is async, rare,
  and privileged. Merging them forces the cheap path to pay the expensive
  path's shape.

**Consequences.** `createIssuerSignedCredential` and
`createDemoWalletPresentation` are now async, which propagated to their
callers. The KMS adapter is a drop-in replacement requiring no changes to
credential issuance code. `tests/unit/issuer-signer.test.ts` asserts no
private key is reachable through the signer surface — that test is the
guarantee the KMS work depends on.

**Out of scope.** The subject's wallet key is deliberately not behind this
boundary: it belongs to the user, not the issuer, and moves to the device
(see CD-4).

---

## CD-7 — sr25519 for identity proof of possession

**Decision.** A client proves possession of `identity_priv_i` with an sr25519
signature — Schnorr over ristretto255 — via `@scure/sr25519`, injecting the
identity scalar into the library's 64-byte secret. `identity_pub_i` is then the
sr25519 public key directly. Spec: `docs/IDENTITY_SIGNATURES.md`. Vectors:
`docs/identity-signature-vectors.json`.

**Problem.** `IDENTITY_DERIVATION.md` has always required "a signature over the
registration challenge with `identity_priv_i`" and no scheme existed to provide
it. WatZappa then made the gap urgent: it derives Matrix account names from
`identity_pub_i`, and a public key is public — presenting it proves nothing, so
anyone who learned it could claim the account.

**Rejected alternatives.**

- *Reusing the atproto DID key,* as community governance votes do
  (`community-governance-signatures.md`). Signing with the DID key **is** the
  linkage the identity system exists to remove. Unusable at any strength.
- *Transposing Monero's `generate_signature` to ristretto255.* Sound, and the
  natural sibling to CD-4's Monero-derived derivation. Rejected on operational
  grounds rather than cryptographic ones: it is an implementation we would own
  and would need review that PARA has no one to perform. Retained as the
  documented fallback if the dependency ever becomes untenable.
- *A separate Ed25519 signing key per identity.* Standard and well-supported,
  but nothing binds it to `identity_pub_i`. Every way of adding that binding is
  worse: sign the binding with the identity key (Monero's option plus an extra
  key), store the pair server-side (a linkage table), or derive accounts from
  the signing key instead (forks this spec).
- *Signal's poksho / zkgroup.* The closest production system to our threat
  model, also on ristretto255, and the source of the labelled domain-separation
  discipline used here. Rejected as a dependency: Rust-only, no React Native
  binding, and it solves zero-knowledge proofs of arbitrary statements where we
  need proof of one discrete log.

**Consequences.**

- **The scalar must be cofactor-shifted.** sr25519 stores the key half as
  `scalar << 3` and divides by 8 on read. A raw scalar silently produces a
  *different* public key — no error, just a different account. This is the
  load-bearing detail of the scheme and is asserted by the vector generator,
  which refuses to emit vectors if it does not hold.
- **Nonces are synthetic**, not the purely random nonce Monero uses. The stored
  nonce seed derives from the identity key and `sign()` mixes fresh randomness
  on top, so neither a dead RNG nor a repeated message can reuse a nonce on its
  own. Nonce reuse in Schnorr publishes the private key.
- **Purpose is inside the signed bytes.** mubEZ registration and WatZappa's
  `para-idp` sign with the same key; a signature for one must be structurally
  unable to verify as the other.
- **Verification never throws.** `@scure/sr25519` raises on a malformed point,
  and a null body raises before any field is read; on a public endpoint that is
  a 500 instead of an auth failure.
- **The vectors pin encoding and public keys, not signature bytes.** sr25519
  signatures are randomized; requiring byte-equality would break on a library
  upgrade that changed nonce handling without changing the scheme.
- `@scure/sr25519` becomes a dependency of both mubEZ and iM8. Same author as
  `@noble/curves`, already relied on; audited by Oak Security, Aug 2025.

**Related.** WatZappa records the Matrix-side consequence as CD-M4 in
`docs/MATRIX_V2.md`.

---

## CD-8 — Proof artifacts are signed once at issuance (`para.artifact.v1`)

**Decision.** Every row written to `proof_artifacts` is attested with an
sr25519 signature over a fixed 15-field canonical encoding (prefix
`para.artifact.v1`, newline-joined), signed **once at issuance** and stored in
the new `attestation_json` column. The client (iM8) verifies with the
byte-identical encoding in `src/services/artifactVerification.ts` and a
pinned issuer list; the published vector in
`docs/artifact-attestation-vectors.json` is asserted by tests on both sides.

**Problem.** Until now the client rendered whatever `outcome` the broker sent:
a compromised broker, an intermediary or a plain server bug all looked the
same as a genuine verification. The attestation is what separates a verifier
from a viewer — it had to be cryptographic, and it had to be stable.

**Details that carry the decision.**

- **Signed at issuance, never re-derived.** sr25519 signatures are randomized
  (CD-7): re-signing on read would change the bytes between fetches. A stored
  proof artifact is evidence; evidence must not silently change. Rows created
  before this change simply have no attestation and verify as `unsigned` —
  the client's honest state, unchanged in meaning.
- **Unset seed means unsigned, not broken.** With no `M8_ARTIFACT_ISSUER_SEED`
  the broker behaves exactly as before. A missing key is a visible "cannot
  verify", never a fake verification.
- **sr25519, not the Ed25519 of `issuerKeyStore`.** The client contract, the
  canonical encoding and both repos' shared infrastructure already speak
  sr25519 (CD-7 family); the attestation is the same scheme, same library,
  same audit trail. The Ed25519 JWK issuer keys remain for credential signing,
  a different artifact type with different rotation needs.
- **Trust is pinned client-side.** `EXPO_PUBLIC_M8_TRUSTED_ISSUERS` on the
  client is where issuer public keys are trusted — never fetched from this
  broker, or verification is theatre.
- **Vectors pin the encoding and public key; signature bytes are reproducible
  only with the pinned nonce entropy** published alongside, for cross-repo
  contract tests. Same principle as CD-7's vectors.

**Rejected alternatives.**

- *Sign on read, no storage.* Rejected for the randomized-nonce reason above:
  every `GET /session` would mint new signature bytes for the same artifact.
- *Deterministic nonces to make read-time signing stable.* Rejected: nonce
  determinism is a foot-gun the scheme deliberately avoids (CD-7's synthetic
  nonces exist precisely because nonce reuse publishes the private key), and
  it buys nothing over storing the one signature that matters.
- *Ed25519 with the existing issuer JWKs.* One more algorithm in the client
  for no gain; see above.

**Related.** iM8's `artifactVerification.ts` (the verifier this satisfies) and
`__tests__/artifactAttestationVector.test.ts` (the cross-repo assertion).

---

## CD-9 — Identity registration receives a public key with proof of possession, stored standalone

**Decision.** A PARA identity is registered by the client sending
`identity_pub_i` and an sr25519 proof of possession over the registration
challenge (CD-7, purpose `mubez-registration`), one HTTP request per identity.
The server verifies the signature against the supplied public key and stores
that key **standalone**: no column, foreign key or index relates it to a
session, a seed, a view key, or another identity's public key. This is the
registration contract `IDENTITY_DERIVATION.md` has always named and never
implemented, now pinned as a decision.

**Problem.** The shipped model is the exact inverse of the derivation spec, on
every axis that matters:

- **The server invents the identity.** `createAnonymousIdentity(sessionId, …)`
  generates a random 32-byte `secret` server-side, stores
  `nullifier_secret_hash = sha256(secret)`, and returns a row the client never
  had a key for. iM8 holds `identity_priv_i` (`keyDerivation.ts`) and sends only
  display metadata (`surface`, `displayName`). The keyholder proves nothing; a
  bystander who reaches the endpoint gets an identical row.
- **Identities are keyed by session.** `anonymous_identities.session_id` is
  `NOT NULL REFERENCES sessions(session_id)`, indexed by
  `idx_anonymous_identities_session`. `IDENTITY_DERIVATION.md` forbids this by
  name: *"No table may relate two identity public keys, or an identity key to a
  seed, view key, or another identity's session."* The session FK is that
  relation. Every one of the ~28 `getSessionId`-scoped call sites in
  `app/controllers/anonymous_controller.ts` reads identity through it.
- **There is no `identity_pub` column at all.** The public key the whole scheme
  is built on is absent from storage; the server has never seen one.

WatZappa made the gap load-bearing: after CD-M1 the Matrix account name is
`H(identity_pub_i)` and the server cannot compute it (MATRIX_V2 F7). Membership
projection, the OD-6 join seam and the private vote path all wait on a server
that can verify possession of an identity key without holding a linkage table —
which is this contract.

**Rejected alternatives.**

- *Keep session-scoped rows, add `identity_pub` beside them.* The additive,
  low-churn option, and wrong: the session FK is the linkage the spec removes,
  so leaving it makes `identity_pub` decorative while the correlation the scheme
  exists to prevent still sits one column over. Half-measures here fail closed
  only by accident.
- *Let the server keep minting the nullifier secret.* Convenient — no client
  change — but it means the server knows the secret behind every anonymous
  identity, so "anonymous" is anonymous to other users and transparent to the
  operator. Same class of defect as OD-7 §5a's server-side vote nullifier, and
  the same fix: the secret is client-derived, the server verifies a proof.
- *One registration transaction for all identities of a user.* Batching is the
  obvious efficiency and reintroduces the linkage at the transport layer: a
  shared request, token or session correlates the keys even with no table.
  `IDENTITY_DERIVATION.md` already requires one unbatched, uncorrelated request
  per identity; this decision inherits that.
- *Register the ballot identity here too.* Rejected by OD-7 Reading A: `civic`
  (index 1) never signs. It is not an `anonymous_identities` row, does not
  authenticate, and is proven-about at vote time, not registered. The signing
  allowlist (`isMatrixIdentityLabel`, `SIG_PURPOSES`) must keep refusing it; see
  OD-7 for the binding-proof path that replaces a registration signature there.

**Consequences.**

- **Burner identities become derived keys, not server rows.** The shipped table
  lets a session own arbitrarily many identities (main, per-community, pajareo,
  `burn_after`). The derivation spec has three fixed indexes (0/1/2) and
  reserves ≥3 for per-community burners **under a future `/v2` tweak label**
  (`IDENTITY_DERIVATION.md` §Identity indexes). Under this contract a burner is
  a distinct client-derived `identity_pub` registered on its own, not a row the
  server spins up — so the burner scheme is blocked on the `/v2` derivation, and
  the tiering (`tier: 'main' | 'burner'`) the client renders today has no
  cryptographic backing yet. This must be resolved before burners ship, not
  after.
- **The ~28 session-scoped call sites are the migration (F2b).** Each read that
  resolves an identity through `session_id` becomes a per-request proof of
  possession against the presented `identity_pub`. The FK and its index are
  dropped last, once nothing reads them. `nullifier_secret_hash` derived from a
  server secret is removed in the same pass (its replacement is client-anchored,
  per OD-7 §5a).
- **Verification is fail-closed and never 500s.** Reuses CD-7's wrapped verifier:
  a malformed point or null body is an auth failure, not a server error, on what
  becomes a public registration endpoint.
- **This supersedes** the registration section of `IDENTITY_DERIVATION.md` by
  making it normative and testable, and it is what OD-7 §7's open checkbox
  "registration binds one ballot identity per credential" builds against for the
  ballot side.

**Related.** WatZappa MATRIX_V2 F7 (unimplementable push projection), OD-6 (join
seam), OD-7 (ballot identity registration, Reading A). iM8
`keyDerivation.ts` / `identitySignature.ts` (the client half, already shipped).
