# Identity Derivation Specification (v1)

How a user's single secret seed becomes the three PARA identities (public,
civic, anonymous) as three unlinkable public keys, with all secret material
staying on the client.

**Status:** normative for iM8 (client, canonical implementer) and mubEZ
(server, receives public keys only). The reference implementation lives at
`tests/helpers/identityDerivation.ts` and must never be imported by server
runtime code: the server never holds a seed, a private key, or the view key.

## Design goals

1. **One backup, three identities.** The user backs up a single 32-byte seed
   (as a BIP-39 mnemonic). Everything else is deterministically re-derivable.
2. **Unlinkable by the server.** mubEZ receives three independent public keys
   at registration. Without `view_priv`, no party can link them to each other
   or to the master `spend_pub`. There is no server-side row that relates them
   (this replaces the `person_roots`/`person_aliases` linkage).
3. **Monero-style additive derivation.** Identities are tweaked variants of
   one spend key, like Monero subaddresses. The holder signs for identity `i`
   with `spend_priv + t_i`; a future auditor holding only `view_priv` can
   recompute the public keys but cannot sign.

## Primitives

| Primitive | Choice |
|---|---|
| Group | ristretto255 (prime-order group over Curve25519) |
| Generator | `G`, the ristretto255 base point |
| Group order | `l = 2^252 + 27742317777372353535851937790883648493` |
| Hash-to-scalar | `H_s(x) = LE(SHA-512(x)) mod l` (interpret digest little-endian) |
| Scalar encoding | canonical 32-byte little-endian |
| Point encoding | 32-byte ristretto255 canonical encoding |

Implementation note: `@noble/curves` (`RistrettoPoint`) provides all of the
above on both Node and React Native/Hermes.

## Derivation

```
seed        : 32 bytes from a CSPRNG, encoded for backup as BIP-39 (24 words)

spend_priv  = H_s("m8/derive/spend/v1" ‖ seed)
view_priv   = H_s("m8/derive/view/v1"  ‖ seed)
spend_pub   = spend_priv · G

t_i         = H_s("para-id/v1" ‖ LE32bytes(view_priv) ‖ u32_LE(i))
identity_priv_i = (spend_priv + t_i) mod l
identity_pub_i  = spend_pub + t_i · G        (= identity_priv_i · G)
```

Domain-separation labels are ASCII, no length prefix, versioned with `/v1`.
`u32_LE(i)` is the identity index as 4 little-endian bytes.

### Identity indexes

| Index | Label | Purpose |
|---|---|---|
| 0 | `public` | The user's public-facing PARA identity |
| 1 | `civic` | Civic participation (ballots, delegation) |
| 2 | `anonymous` | Anonymous posting surface |

Indexes ≥ 3 are reserved. A future need for per-community burner identities
extends the tweak input, in a `/v2` label, rather than reusing these.

## Registration contract (mubEZ)

- The client registers each identity by sending only `identity_pub_i` and a
  signature over the registration challenge with `identity_priv_i`
  (proof of possession). **The scheme is specified in
  `IDENTITY_SIGNATURES.md`** (CD-7) — sr25519 with the identity scalar injected;
  until that document existed this contract named a signature no implementation
  could produce. One request per identity; requests must not be
  batched, correlated by shared tokens, or tied to one session, or the
  transport layer recreates the linkage this spec removes.
- The server stores each public key standalone. **No table may relate two
  identity public keys, or an identity key to a seed, view key, or another
  identity's session.**
- Key rotation and recovery are out of scope for v1 (a lost seed means new
  identities; social recovery arrives with the backup ceremony work).

## Security properties

- **Unlinkability:** for anyone without `view_priv`, `identity_pub_i` values
  are independent uniform-looking group elements; linking them to each other
  or to `spend_pub` requires solving DDH-style problems in ristretto255.
- **View-only audit:** a holder of (`spend_pub`, `view_priv`) can recompute
  every `identity_pub_i` but cannot produce signatures. This is the hook for
  future selective-disclosure and recovery flows.
- **No key-reuse across domains:** signatures for identity `i` use
  `identity_priv_i`, never `spend_priv` directly. `spend_pub` itself is never
  sent to the server.
- **Seed compromise is total:** everything derives from the seed. This is by
  design (one backup) and is why the seed lives only in the device secure
  store and its backup mnemonic.

## Test vectors

`docs/identity-derivation-vectors.json` — three fixed seeds with all derived
scalars and public keys. iM8's implementation MUST reproduce the file byte for
byte; `tests/unit/identity-derivation.test.ts` pins the reference
implementation to it and verifies the additive property
`identity_pub_i = spend_pub + t_i·G` independently of the private path.

Regenerate (only when the spec version changes, never silently):

```
pnpm exec tsx scripts/generate-derivation-vectors.ts
```
