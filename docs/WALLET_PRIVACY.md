# Wallet presentation privacy (v2)

What `m8.identity.presentation.v2` protects, what it does not, and who can
link what. Read with CD-13 and CD-14 in `CRYPTO_DECISIONS.md`.

**Summary.** v2 gives integrity (claims are exactly what the issuer signed,
presented by the key the issuer bound) and claim minimization (the
`basicCredential` omits `curp_hash` and `district_hash`). It does **not** give
anonymity, unlinkability or selective disclosure. Every presentation carries
the account DID and identifiers that stay the same from one presentation to the
next.

## What a v2 presentation contains

| Field | Stable across presentations? | Notes |
|---|---|---|
| `credential.subjectDid` | Yes, forever | The account's AT Protocol DID. Public, resolves to a handle and profile. |
| `credential.id` | Yes, per credential | |
| `credential.holderPublicKey` | Yes, per enrollment | Shared by `credential` and `basicCredential`. |
| `credential.revocationHash` | Yes, per enrollment | Shared by both credentials. Published on the public CRL (`GET /identity/crl`) once revoked. |
| `credential.issuedAt` / `expiresAt` | Yes, per credential | Millisecond timestamps; `expiresAt` is identical on both credentials of an enrollment. |
| `credential.claims` | Yes | The whole credential, not just the disclosed claims. |
| `requestId`, `nonce`, `issuedAt` | No | Per request. |

An age-only request answered with `basicCredential` reveals, besides
`age_over_18`: the account DID, `citizenship: "MX"`, and — through the presence
or absence of `age_over_21` — whether the holder proved 21+. `age_over_21` is
only included when proven, so its absence separates 18–20-year-olds from those
who did not prove it, not from each other.

## Who can correlate what

The current architecture routes every presentation through mubEZ: the holder's
wallet submits it to `/identity/verify` on the holder's own M8 session, and the
requesting client (PARA) reads back a minimal result. A relying app therefore
normally sees the result, not the presentation. The map also covers a verifier
that receives the raw presentation, because the format is portable and any
client that forwards it hands all of it over.

### An age-only verifier (the relying app behind an `audienceAppId`)

- **Via the result** (`GET /identity/request/:id`): `valid`,
  `disclosedClaims`, `revealedClaimIds`, `issuerDid`, `checkedAt`. No subject,
  credential or holder key. But the request was created inside the holder's
  own session, so the app running in PARA already knows the account.
- **Via a forwarded presentation:** everything in the table above.
- **Across its own presentations:** links all of them, by `subjectDid`, and
  even without it by credential id, holder key or revocation hash.

### Another verifier, or verifiers comparing notes

- Any two that saw presentations of the same enrollment link them by
  `subjectDid`, `holderPublicKey`, `revocationHash` or `expiresAt`, whether one
  saw the basic credential and the other the full one.
- A verifier that received the full credential holds `curp_hash`, which is
  the same for every account of the same person (a deterministic peppered
  HMAC of the CURP). It can join that person's accounts, and through the shared
  holder key and revocation hash, attach `curp_hash` to that person's age-only
  presentations elsewhere.
- Anyone can watch the public CRL and learn when a revocation hash they saw
  was revoked.

### mubEZ (the running service)

mubEZ is issuer, relay and verifier, and is fully trusted for privacy in v2.

- At issuance it receives the INE data in the request body (name, CURP,
  birth date, address; simulated in this build) and the holder public key.
- At every presentation it knows the session, hence the DID, the audience
  app, purpose, requested elements, time and client network metadata.
- It can link every presentation of a person across accounts through
  `person_key` / `curp_hash`.

### A database operator (anyone with a copy of the SQLite file)

| Table | Holds |
|---|---|
| `sessions` | session ↔ DID ↔ handle |
| `identity_requests` | per session: audience app, purpose, requested elements, created/used time, indefinitely; `result_json` until the requester reads it once |
| `proof_artifacts` | per session: `revocation_hash`, ZK `commitment`, `person_key`, and a statement containing `curp_hash` |
| `ledger` | `curpHash`, `commitment`, `revocationHash`, both credential ids, issuer key id |
| `wallet_binding_requests` | session ↔ holder public key, and issued credentials until collected; rows pruned lazily after expiry |
| `nullifiers` | `(nullifier, community_id)` only, since CD-16 (v1 also stored commitment and session) |

From these an operator can reconstruct: account → INE person → every
audience app the account presented to, when, and for what purpose. Not in the
database: presentation bodies, holder private keys, raw CURP, the ZK salt.
With the `CURP_PEPPER` (environment, not database), `curp_hash` reverses to the
CURP by enumeration.

## Stolen credential vs stolen holder key

- **Stolen credential** (a copy of the JSON): unusable. Presenting needs a
  signature by the issuer-bound holder key.
- **Stolen holder private key** (an unlocked stolen phone, or malware reading
  the Keychain/Keystore item after unlock): the attacker can present, but only
  inside a session for the same DID, so they also need that account's session
  tokens, which a stolen phone has.
  - *Mitigations in place:* the key is device-only (never synced, never in
    backups) and each read needs user presence (biometrics or passcode).
    Recovery revokes the enrollment by artifact id from any signed-in device.
  - *Not in place:* revoking the lost device's session tokens as part of that
    recovery, and a non-exportable hardware key (the Secure Enclave has no
    Ed25519).

## Wording

Do not describe v2 sharing as anonymous, private, unlinkable, zero-knowledge
or selective, or say that "only proofs are shared". Say what it is:
full-credential, includes the account DID, and apps can link repeated shares.
Corrected in this pass:

- mubEZ: the `spark` persona summary ("selective disclosure contexts"), in
  code and in both locales; README's "privacy-preserving identity flows".
- iM8: the INE verification modal ("only proofs are shared with apps", "Raw
  data stays private"), onboarding ("prove only what each civic action
  needs").
- PARA: the wallet's claim picker ("Choose which verified claims to reveal…
  You control your data", "🔒 End-to-end encrypted") and its fake presentation
  QR were removed; the INE success screen ("verified anonymous citizen").

Wording about burner voices and anonymous posting personas belongs to the
separate anonymous-identity features and was left alone. Onboarding's
"Each card can carry granular ZKP proofs" was not verified in this pass.

## Release blockers

The PARA gate (`WALLET_HOLDER_KEY_SUPPORTED`), the iM8 gate
(`HOLDER_WALLET_ENABLED`), simulated INE in production, and
`INE_INTEGRATION_APPROVED` stay closed until:

1. **Device tests** on the target iOS and Android devices:
   - the key survives restarts and app updates;
   - every read prompts for user presence;
   - the item is absent from backups and from a restored device;
   - it becomes unreadable after a biometric change, and the wallet then
     reports it lost and recovers.
2. **A real issuer integration:** INE approval, a production issuer key out of
   environment variables, the issuer key pinned in iM8 (`trustedIssuerKeys`),
   and real INE verification instead of simulation.
3. **Age proofs bound to the issuer.** The age proof accepted at issuance is
   not bound to the INE birth date (see `V3_UNLINKABLE_AGE_PROOFS.md`); a real
   issuer must check the birth date itself.
4. **iM8 approval screens** for binding and presenting that render
   `planPresentation` in full: every revealed claim and every linkable
   identifier.
5. **Session revocation** for the lost device as part of recovery.
6. **A retention limit** for `identity_requests` (audience and purpose
   history is kept indefinitely).
7. **Unlinkable age proofs (v3).** Required (CD-15): age checks must leave no
   trace, and v2 cannot provide that. v2 is not released for age checks.
