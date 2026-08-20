# PARA Identity Signatures

Companion to `IDENTITY_DERIVATION.md`. That document defines how identity keys
are derived; this one defines how a client proves it holds one.

Decision record: `CRYPTO_DECISIONS.md` CD-7.
Shared vectors: `docs/identity-signature-vectors.json`.

---

## Why this exists

`IDENTITY_DERIVATION.md` already promises this in its registration contract —
*"a signature over the registration challenge with `identity_priv_i` (proof of
possession)"* — and until now no scheme existed to satisfy it. Two consumers
need it and must not diverge:

| Consumer | Purpose string | What it proves |
|---|---|---|
| mubEZ registration | `mubez-registration` | The client holds the key it is registering |
| `para-idp` → Matrix (WatZappa) | `matrix-login` | The client holds the key its MXID derives from |

The Matrix case makes the requirement sharp. WatZappa derives a Matrix
localpart from `identity_pub_i` (`MATRIX_V2.md` CD-M1), and a public key is by
definition public. Presenting the key proves nothing; **anyone who learns it
could claim the account.** The signature is what closes that gap.

## Scheme

**sr25519** — Schnorr over ristretto255 — via `@scure/sr25519`. The identity
scalar is used directly, so `identity_pub_i` *is* the sr25519 public key. No
second key, no binding to prove, no server-side mapping.

### The one detail that matters

sr25519 stores the key half of its 64-byte secret **cofactor-shifted**:

```
secret[0..32]  = LE32( (identity_priv_i << 3) mod 2^256 )   # schnorrkel's
secret[32..64] = nonce seed                                 # Ed25519-compatible
                                                            # format
```

`getPublicKey` divides by 8 on read, recovering the scalar. **Injecting a raw
scalar produces no error — it silently yields a different public key**, and
therefore a different account. Every implementation must apply the shift.

Lossless for every scalar below the group order: `x << 3 < 2^255` fits the
256-bit mask, so the shift never truncates. Verified over 20,000 random scalars.

### Nonce seed

```
nonceSeed = SHA-512("para-id/sig-nonce/v1" ‖ LE32(identity_priv_i))[0..32]
```

Deterministic, so a device restored from the seed produces the same secret. The
per-signature nonce is *not* this value: `sign()` additionally mixes fresh
randomness, making the scheme **synthetic**. A dead RNG cannot repeat a nonce on
its own, and a repeated message cannot either. Nonce reuse in Schnorr does not
degrade security, it publishes the private key — `x = (r₁−r₂)/(c₂−c₁)` — which
is why neither input is trusted alone.

## Signed payload

```
type       "para.identity.pop.v1"
purpose    "matrix-login" | "mubez-registration"
audience   the verifier's identifier, e.g. "para-idp"
identityPub hex(identity_pub_i), 64 characters
challenge  server-issued, single-use, base64url
signedAt   RFC 3339 UTC
```

### Canonical encoding

Signed bytes are these seven strings joined with `\n` (U+000A), UTF-8, no
trailing newline:

```
"para-id/sig/v1" ‖ LF ‖ type ‖ LF ‖ purpose ‖ LF ‖ audience ‖ LF ‖
identityPub ‖ LF ‖ challenge ‖ LF ‖ signedAt
```

Field order is fixed by construction, not by JSON key ordering, so a verifier in
another language cannot disagree about what was signed. The domain string
`para-id/sig/v1` is the first line and is inside the signature.

**Purpose is inside the signed bytes.** Both consumers sign with the same key,
so a `mubez-registration` signature must be structurally unable to verify as a
`matrix-login` one. Monero's plain `generate_signature` leaves domain separation
entirely to callers and its own proof code had to grow a versioned
`HASH_KEY_TXPROOF_V2` constant to fix the resulting confusability; we start
where they ended up.

## Verifying

A verifier MUST reject unless all of the following hold:

1. `type` is exactly `para.identity.pop.v1`.
2. `purpose` equals the purpose the verifier expects. Never accept "any".
3. `audience` equals the verifier's own identifier.
4. `challenge` matches an outstanding, unexpired, **single-use** challenge, then
   is consumed. mubEZ already has this in `src/services/issuanceChallenge.ts`.
5. The sr25519 signature verifies over the canonical encoding.

The verifier holds no private key material and needs none.

**Reject, never throw.** `@scure/sr25519`'s `verify()` raises on a malformed
point, and a null request body raises before any field is read. On a public
endpoint that turns attacker-controlled garbage into a 500 instead of an auth
failure. Every failure path must return false.

## Identity boundary

**The `civic` identity (index 1) must never produce a signature.** It is the
ballot identity — *"Civic participation (ballots, delegation)"* — and signing
with it anywhere outside a ballot recreates the linkage this whole design
removes. Signing APIs must enforce an **allowlist** (`public`, `anonymous`), not
a denylist, so indexes reserved for future use fail closed.

Note the naming trap: `civic` sounds like a community identity and is the ballot
identity. `anonymous` (index 2) is the community-facing one.

## Test vectors

`docs/identity-signature-vectors.json`, regenerated only on a spec version bump:

```
pnpm exec tsx scripts/generate-signature-vectors.ts
```

**What the vectors pin, and what they deliberately do not.** They pin the
canonical `encoded` bytes and the derived `sr25519PublicKey` exactly — those are
this specification, and an implementation that differs is wrong. They include a
`signature` that every implementation MUST **verify**, but MUST NOT be expected
to reproduce byte for byte: sr25519 signatures are randomized, and pinning the
bytes would make the vectors fail on a library upgrade that changed internal
nonce handling without changing the scheme. Verification is the interop
contract; byte-equality of a randomized signature is not.
