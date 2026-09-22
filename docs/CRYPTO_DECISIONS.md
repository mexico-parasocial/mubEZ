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
  cryptographic backing yet. **Decided 2026-09-18: burners are deferred.** F2b
  makes the three fixed identities (0/1/2) register and authenticate correctly;
  the `/v2` per-community burner derivation and any server-invented burner rows
  are out of its scope. Until then the client's `burner` tier is presentational
  only and must not be described as an unlinkable identity.
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

---

## CD-10 — Per-request proof of possession for anonymous mutations, modeled on the M8 assurance / DPoP pattern

**Decision.** The anonymous-surface mutations (create / update / link-post /
link-germ / follow) authorize by a **per-request proof of possession of the
`anonymous` identity key**, not by session.

**Correction (2026-09-18), before this was built upon.** An earlier draft of
this decision said mubEZ should "mirror field-for-field" and "share one
implementation" with the PDS `m8-assurance-store`/`verifier`. Reading the PDS
code showed that is the wrong frame, in two ways:

1. **Opposite direction and scheme.** The PDS m8-assurance is a **broker→PDS**
   protocol: mubEZ (the M8 issuer) signs an **Ed25519 JWT**
   (`application/para-m8-assurance+jwt`) and the *PDS* verifies it against
   mubEZ's JWKS and consumes the nonce+jti. The CD-10 anon-action proof is the
   other way round — **client→broker** — and is a raw **sr25519** PoP of the
   identity key that *mubEZ* verifies. Different direction, different signature
   scheme; they are not the same verifier and cannot be one.
2. **The replay store is per-role, not shared at runtime.** Each verifier
   consumes nonces in its own service: the PDS store lives on the PDS (for the
   assurance JWT), the anon-action store lives on mubEZ (for the PoP). They are
   different service processes with different DB layers (kysely/Postgres vs
   `better-sqlite3`), so there is no single store instance to share, and a
   cross-repo runtime package is not viable here (three separate git repos,
   incompatible dependency trees).

**What "share it" actually means here (decided 2026-09-18):** share the
*contract*, the same mechanism that already shares CD-7's sr25519 scheme between
mubEZ and iM8 — a written spec plus test vectors that each side pins. Concretely:

- The **replay-consume algorithm** (issue a hashed single-use challenge with an
  expiry and a pending-count cap; consume by atomically marking the nonce spent
  `WHERE consumedAt IS NULL` **and** inserting the `jti` with conflict-ignore)
  is specified once and implemented identically on each side against its own DB.
  The PDS `m8-assurance-store.consume` is the reference behaviour to match.
- The **anon-action PoP encoding** reuses CD-7 and its existing shared vectors
  (`identity-signature-vectors.json`), extended with the `anon-action` purpose.
- **Convergence target:** mubEZ implements *both* assurance roles it owns — the
  Ed25519 assurance-JWT **issuer** (its unbuilt half of the broker→PDS protocol,
  the "acuerdo contra el broker real" gap in INFORME_AVANCE_PARA_ES.md) and the
  sr25519 anon-action **verifier** — over **one** replay-consume implementation
  inside mubEZ, so the broker has a single, tested replay primitive rather than
  two divergent copies. That is the sharing that is real and achievable.

**Problem.** F2b removes the `session_id` link from `anonymous_identities`
(F2B_SESSION_MIGRATION.md). Once it is gone, the mutation endpoints can no longer
answer "whose identity is this?" from the session. They need to answer it from a
proof that the caller holds the identity key — per request, because a
session-scoped proof would just move the linkage into whatever holds the session.
The registration proof (CD-9) establishes the key exists; it does not authorize a
later mutation.

The naive version — a lone freshness-bounded signature — is replayable inside its
window and binds to nothing. This was about to be hand-rolled in mubEZ before it
was noticed that the reviewed primitive already exists (credit: the tranquil-pds
device-session lineage and the atproto DPoP model it follows).

**The pattern to mirror** (from `m8-assurance-store`):

- **Server issues a single-use challenge**: a 256-bit nonce, stored **hashed**
  (`nonceHash`), with an expiry and a cap on pending challenges per caller to
  bound abuse. The raw nonce is returned once and never stored.
- **The client signs a proof** binding: the `anonymous` identity key
  (`identity_pub`), the action, the audience, the server nonce, and a client
  `jti` (one-time id), under a new signing purpose **`anon-action`** so a
  mutation proof can never verify as a `matrix-login`, `mubez-registration`, or
  `message-approve` (purpose is inside the signed bytes — CD-7).
- **The server consumes atomically**: mark the nonce consumed
  (`WHERE consumedAt IS NULL`, bound to the presenting key) **and** insert the
  `jti` with `ON CONFLICT DO NOTHING` — the double guard that makes a replay fail
  even if two requests race. This is exactly `m8-assurance-store.consume`.

**Rejected alternatives.**

- *A lone content-committing signature (message-approve style), no server nonce.*
  Simpler and one fewer round-trip, but replayable within the freshness window
  and with no server-side single-use guarantee. `message-approve` accepts this
  because a replayed message approval is low-harm; a replayed identity mutation
  is not.
- *A bespoke single-nonce store in mubEZ.* What was almost built. Rejected: a
  lone nonce with no jti is a weaker guard than the PDS store's reviewed
  nonce+jti double-consume, and building a second divergent replay primitive is
  what the sharing decision above exists to prevent. mubEZ gets **one**
  replay-consume implementation matching the PDS reference, used by both broker
  roles.
- *Reuse the CD-9 registration challenge table as-is.* Its rows are purpose-blind
  nonces, so it would function, but the name and single-guard (nonce only, no
  jti) are registration-shaped. The action path wants the nonce+jti double guard;
  generalize the store to carry both rather than overloading the registration
  table.

**Consequences.**

- `anon-action` is added to `SIG_PURPOSES` on both the mubEZ verifier and the iM8
  signer. The signer's Matrix allowlist still refuses `civic`, so the ballot key
  cannot sign a mutation either.
- A challenge store carrying `nonceHash`, `jti`, `consumedAt`, expiry and a
  pending cap is added to mubEZ, mirroring the PDS schema field-for-field so the
  two can later share one implementation. It is keyed by the nonce/jti, never by
  a session.
- This is the mechanism F2B_SESSION_MIGRATION.md step 1 depends on: only once the
  mutation endpoints verify an `anon-action` proof can they resolve by
  `identity_pub` and the `session_id` FK be dropped. Until the client sends the
  proof, the endpoints keep the session path (additive cutover).
- Convergence is the point: the same proof shape should ultimately let the PDS
  `m8-assurance-verifier` and the mubEZ broker validate against one contract.

**Related.** CD-9 (registration), CD-7 (the sr25519 proof primitive and purpose
binding), OD-7 (ballot key never signs). Reference implementations:
`WatZappa-permissioned-data/packages/pds/src/account-manager/m8-assurance-store.ts`
and `.../m8-assurance-verifier.ts`. Device-session lineage: tranquil-pds
(`WatZappa/services/matrix-bridge/.../identity-matrix.ts`).

---

## CD-11 — Votes bind to the civic pseudonym; m8 holds no legal identity

**Decision.** A vote is attributable to a person's **civic pseudonym** and to
nothing else. Browsing that pseudonym and seeing how it voted on other subjects
is accepted: an accumulated voting history under one pseudonym is not treated as
a leak. What must never be reachable is the legal identity behind it — real
name, CURP, INE or any other document.

That reduces to one invariant, and it is stated as one line so it can be tested
and watched in review:

> **`person_roots.id` must never become linkable to a legal identity.**

Three rules follow.

1. **An identity check yields claims and discards its inputs.** No raw
   credential — name, CURP, document image — is written to any table, log, queue
   or object store, not even transiently "pending review". The permitted output
   is the claim set already declared in `src/types/index.ts`: `age_over_18`,
   `age_over_21`, `citizenship`, `district_hash`, `curp_hash`,
   `verified_public_figure`.
2. **`curp_hash` stays peppered.** Already decided and built — CD-1,
   `src/services/curpHash.ts`. Recorded here because it is load-bearing for this
   decision rather than incidental to it: an unpeppered CURP hash is enumerable
   offline, which would make the invariant false the moment the database leaked.
3. **`civic` keeps its own key.** It gains the pseudonymous profile people
   browse; it does not merge with `anonymous`.

**Problem.** The privacy target was previously the maximum-privacy reading of
OD-7 §5b — ballots unlinkable even to the server, via Pedersen commitments,
range proofs and CLSAG rings. That is a 2027-scale programme and it was blocking
a pilot that needs to run this year. A smaller target was set deliberately
(OD-7 §5g).

The second half of the problem is that the schema **already satisfies most of
this, by accident rather than by rule**. `mubEZ/src/db/schema.sql` has no column
holding a name, a CURP or a document; `person_roots` is `id`, `session_id`,
`status` and timestamps. Nothing states that it must stay that way, and the
breaking point is identifiable: the day `src/services/ineSimulation.ts` is
replaced by a real INE integration, something will want to persist a document,
and if it lands beside `person_id` the model collapses at once rather than
gradually.

**Rejected alternatives.**

- *Merging the `civic` and `anonymous` keys* to make "civic is anonymous by
  default" literally true. `OD-2-PROOF-OF-POSSESSION.md` §6.5 makes "the ballot
  identity must never sign" its most important review point, and
  `isMatrixIdentityLabel` enforces it by allowing only `public` and `anonymous`.
  Merging would make the key that votes the key that authenticates to Matrix,
  handing it to the chat server. Giving `civic` the visible profile achieves the
  same product intent — one persona the user sees — without moving key material
  across that boundary.
- *Commitments now (§5b).* Unnecessary under the accepted threat model, and it
  would delay the pilot by a programme rather than a sprint. Deferred, not
  abandoned: the ballot format must still not foreclose it.
- *Storing the credential briefly, "pending review".* There is no transient
  store that survives contact with a backup, a log shipper or an incident. The
  rule is written as "never" because "briefly" is unenforceable.
- *A per-user privacy toggle over a record written to the person's own repo.*
  A flag cannot make a published record private: an atproto record is signed by
  its author's DID and sequenced to the firehose, and cannot be unpublished.
  Choosing how much to share has to select **which write happens**, not annotate
  a public one.

**Consequences.** The joins m8 holds — `person_aliases` mapping `person_id` to a
DID, and `civic_vote_nullifiers` mapping `person_id` to every subject voted on —
become **acceptable** under this decision, because the person root carries no
legal identity to join them to.

That is a real change of posture and it contradicts something still written
down: `docs/IDENTITY_DERIVATION.md` forbids any table relating an identity key
to a session, and OD-7 §6 treats `anonymous_identities.session_id` as a defect
to remove across 28 call sites. Under CD-11 those joins are tolerated rather
than forbidden. **Both cannot stand.** Either `IDENTITY_DERIVATION.md` is
amended to say the linkage is permitted while the person root stays anonymous,
or the joins go as originally planned. Left open here deliberately rather than
resolved in passing; whoever takes it should decide it as its own entry.

Residual risk, to be carried into `THREAT_MODEL.md`: under this model a breach
of m8 does not reveal who voted what, because m8 does not know who anyone is —
but it does reveal the full voting history of every pseudonym, and any future
component that learns a legal identity for a `person_roots.id` retroactively
de-anonymises all of it. The invariant is the whole guarantee; there is no
second line behind it.

**Superseded in part by CD-12.** The Consequences paragraph above is wrong: the
joins are not acceptable, because `person_aliases` holds the user's account DID,
written on the vote path itself. The invariant and rules 1-3 stand; CD-12 is
what makes them true.

**Related.** OD-7 §5g (the decision as taken, with what was verified), CD-1
(peppered hashing), CD-9 (registration), OD-2 §6.5 (the ballot key never signs).
Trigger point for rule 1: `src/services/ineSimulation.ts`.

---

## CD-12 — The no-linkage rule stands; `person_aliases` is the defect

**Decision.** `docs/IDENTITY_DERIVATION.md` keeps its rule unamended: *no table
may relate two identity public keys, or an identity key to a seed, view key, or
another identity's session.* The contradiction left open in CD-11 is resolved
**against CD-11**. The joins m8 holds today are not acceptable, and CD-11's
Consequences paragraph — which called them tolerable because the person root
carries no legal identity — is withdrawn.

**Problem.** CD-11 reasoned from the shape of the schema. Reading the code that
writes it gives a different answer.

`issueCivicVoteProof` in `src/services/civicVoteIdentityService.ts` does three
things in sequence: `ensurePersonRoot(sessionId)` creates a person root keyed
`UNIQUE` by `session_id`; `ensureSessionAlias(person.id, sessionId, session)`
writes **the session's own account DID** into `person_aliases`; and
`listActiveAliasDids(person.id)` returns every alias of that person, which is
handed back in the response.

So on the vote path itself, m8 links the person root to the user's
public-facing PARA identity — index 0, the one with a handle and a profile, the
one where a person may put their real name. Any civic pseudonym linked
afterwards shares `person_id` with it.

That does not merely break the older rule. **It falsifies CD-11's own
invariant.** `person_roots.id` is linkable to a legal identity today, by one
join: `person_aliases` → account DID → public profile. CD-11 accepted a
browsable pseudonymous voting history on the premise that nothing joins the
pseudonym to a name. The premise is currently false.

**Rejected alternatives.**

- *Amend `IDENTITY_DERIVATION.md` to permit the linkage while the person root
  stays anonymous* — the option CD-11 floated. Rejected because the linkage in
  the code is not pseudonym-to-anonymous-root; it is pseudonym-to-account, which
  is precisely the path by which a voting history acquires a name. Amending
  would make the rule agree with the code by lowering the rule to whatever the
  code happens to do.
- *Keep `alias_did` for auditability.* One person, one vote needs
  `person_roots.id` and `UNIQUE (person_id, subject_type, subject_uri)` and
  nothing else. OD-7 §5a already established that authorisation runs on
  `person.id` and that `identity_pub_civic` is never presented, so the DID
  columns are observational, not functional. §5a.4 says `aliasDid` has to go on
  its own merits.
- *Fix it after the pilot.* The rows are written on every vote-proof issuance.
  A table of them accumulates whether or not anyone has decided what it is for,
  and deleting it later does not unlink what was already observed.

**Consequences.** Four changes, none of which need new cryptography — the
mechanisms are all decided already:

1. `person_roots` stops being keyed by `session_id`. Identifying the person on a
   request is per-request proof of possession, which is **CD-10**'s mechanism,
   decided for the anonymous surface and not yet applied here.
2. `ensureSessionAlias` is deleted. The account DID never enters
   `person_aliases`.
3. `civic_vote_nullifiers` drops `session_id` and `alias_did` (OD-7 §5a.4).
4. `listActiveAliasDids` stops returning a correlation set to its caller.

Until those land, the privacy property described in CD-11 is not the one the
system has. That belongs in `THREAT_MODEL.md` as a **current-state gap**, not as
residual risk — the difference matters, because residual risk reads as
"accepted" and this is not accepted, only unfixed.

**Supersedes.** The Consequences paragraph of CD-11 (the joins being acceptable).
The rest of CD-11 — the invariant, claims-never-rows, `civic` keeping its own
key — stands unchanged, and CD-12 is what makes the invariant true rather than
aspirational.

**Built 2026-09-21.** Consequences 2, 3 and 4 are done: `ensureSessionAlias` is
gone, `civic_vote_nullifiers` and `person_aliases` lost their `session_id` and
`alias_did` columns (migration 034), the proof no longer accepts or returns a
DID, and the PARA client stopped sending `agent.session.did` (OD-7 §5a.4).

Consequence 1 turned out to be hiding a correctness bug, fixed in the same pass.
`person_roots.session_id UNIQUE` meant a second session minted a second person,
and the only guard deduplicated on the ZK commitment — whose salt the client
chooses — so re-enrolling produced a second person who could vote again on the
same subject. **One person, one vote did not hold.** Migration 035 files person
roots under `person_key` = HMAC(pepper, 'person-root' ‖ `curp_hash`), written
onto the INE artifact at issuance, so every session of the same human resolves
to one root. `tests/integration/civic-vote-identity.test.ts` pins it, and the
test was confirmed to fail against the previous code.

What is *not* done: the session is still one hop from the person, through
`proof_artifacts.session_id`. The person is no longer **defined** by the session
but is still **discoverable** from it, and closing that needs CD-10's
per-request proof of possession on this path.

**Related.** CD-10 (per-request PoP, the remaining hop), CD-1 (the deterministic
`curp_hash` this anchors on), CD-9 (registration), OD-7 §5g and §6 (the 28 call
sites), `IDENTITY_DERIVATION.md` (the rule that stands).


**Canje público y cierre de aliases (2026-09-21, código local).** La ruta de
aliases y su servicio se retiran; la migración 036 elimina la tabla. No se ha
aplicado a la base real. La emisión deja de registrar sesión junto a
nullifier/sujeto/referencia en el ledger. Las entradas antiguas y backups
requieren tratamiento separado; esta entrega no los anonimiza.

El voto público de cabildeo recibe una autorización MAC de m8 ligada al DID de
su sesión, nullifier, sujeto y opción. El verificador devuelve solo estado HTTP.
No se persiste una nueva tabla DID-persona, pero el voto público y el broker
siguen siendo correlacionables: esto **no cumple aún la identidad cívica privada
de CD-12**, ni pretende habilitarla. Las otras familias conservan su formato de
emisión y no adquieren verificación de canje por este cambio. El protocolo
privado y las reglas de publicación permanecen pendientes.
