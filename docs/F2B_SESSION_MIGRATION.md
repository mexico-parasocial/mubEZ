# F2b — migrating the anonymous surface off session scoping

The registration endpoint (CD-9) and the additive bridge
(`anonymous_identities.identity_pub`) are in place. This document classifies
every place `anonymous_identities` is reached by `session_id`, so the cutover to
proof-of-possession can be done site by site without either breaking anti-abuse
or reintroducing the linkage the scheme removes.

**The rule that drives the classification.** Not every use of the session is the
problem. There are two kinds, and only one is forbidden:

- 🔴 **Linkage** — the session is used to answer *"whose anonymous identity is
  this?"*. This is the flecha from an anonymous identity back to the real
  account. It must move to resolution by the registered key (via PoP).
- 🟢 **Operational** — the session is used for something that is *not* identity
  ownership: anti-abuse (device trust), or a defensive guard. It may stay, but
  it must not become a new way to relate an anonymous identity to the account.
- 🟡 **Decision** — a use that links the two today and needs a product/privacy
  decision on how it re-anchors, because there is no mechanical answer.

Status: classification only. No code changed. Nothing is deleted until every 🔴
below resolves by key and the dependent tables re-anchor; the `session_id` FK is
the last thing to go.

---

## 🔴 Linkage — must resolve by registered key

These answer "which identities/posts are this account's" through `session_id`.
The bridge already gives the replacement read path
(`findAnonymousIdentityRowByPub`); each of these moves onto it, gated by a PoP
that the client now sends (iM8 `registerIdentity` / `signChallenge`).

| Site | Today | After |
|---|---|---|
| `requireAnonymousIdentityRow` | `WHERE id = ? AND session_id = ?` | `WHERE id = ? AND identity_pub = ?` (pub from the request's verified PoP) |
| `listAnonymousIdentities` | `WHERE session_id = ?` | resolve by the caller's proven key(s) |
| `createAnonymousIdentity` | inserts `session_id`, server-invented `nullifier_secret_hash` | inserts `identity_pub` from a verified PoP; the server-minted secret goes |
| `ensureDefaultAnonymousIdentity` | first row `WHERE session_id = ?` | keyed off the proven `anonymous` (index 2) identity |
| `ensurePajareoIdentity` | `WHERE session_id = ? AND community_uri = 'm8:pajareo'` | keyed off the proven identity |
| `updateAnonymousIdentity` | ownership via `requireAnonymousIdentityRow` | inherits the resolver change |
| `requireAnonymousIdentity` | wraps the row resolver | inherits it |
| `linkAnonymousPost` / `ownsPost` / `requireAnonymousPost` | post ownership via `anonymous_identities.session_id` (JOIN) | via the identity's `identity_pub` — the posts table itself does not need a session column, it hangs off the identity |
| `updateAnonymousPostStats` / `updateAnonymousPostDmPolicy` | `requireAnonymousPost` (session JOIN) | inherit the post resolver change |
| `linkGermContact` / `unlinkGermContact` | ownership via `requireAnonymousIdentity` | inherit the identity resolver change |

**Note on posts and germ:** they never carry `session_id` themselves — they hang
off `anonymous_identities` via `identity_id`. So once the identity is keyed by
`identity_pub`, posts/germ re-anchor automatically through the identity. There is
no separate posts/germ re-keying to design; the earlier worry was overstated.

---

## 🟢 Operational — session stays, must not leak identity

| Site | Why it stays |
|---|---|
| `getDeviceTrustSummary(sessionId)` / `assertTrustedDevice(sessionId)` | Anti-abuse. Device trust is about *this device*, not *who you are*; a thousand fake identities are stopped by the device check, not by the identity. Session/device-scoped is correct. |
| `getSessionIdentity(sessionId).did` inside `linkGermContact` | Used **defensively**: it fetches the real DID only to reject a contact URL that contains it (`ANONYMOUS_GERM_DID_LEAK`). This is an anti-leak guard, the opposite of linkage — it must be kept. |

**Guard to add:** the `device_trust_state` column stored *on the identity row*
must not become a back-channel that correlates identities sharing a device.
Verify it holds only a coarse status, never a device id, before the FK drops.

---

## 🟡 Decisions needed before the FK can drop

These relate the anonymous identity to the account today and have no mechanical
re-anchor. They are the real blockers, and they are product/privacy calls.

**D1 — Proof badges and verification.** `listPublicProofBadges(sessionId)` and
`hasActiveParaVerification(sessionId)` read the *account's* proof artifacts by
session and stamp them onto the anonymous identity's public card
(`hydrateIdentityCard`, `getAnonymousContactEligibility`). That is a real link:
"this anonymous voice carries the badges of the account behind it." The badges
are the point of the feature (a verified anonymous voice), so they cannot just
be dropped. The question: does a badge attach to the *identity key* (proven
about that key, e.g. a credential the client presents per identity) rather than
resolved from the session's records? Until decided, badges keep the identity ↔
account link alive even after the FK goes.

**D2 — The ledger.** `writeLedger(sessionId, 'Anonymous…', 'anonymous_identity',
id, …)` writes an audit row relating a session to actions on a specific
anonymous identity. That is linkage by audit log — precisely what the threat
model says audit must not record. Decision: drop the identity-scoped ledger
entries, or re-scope them so an entry never relates a session to an anonymous
identity id. (Operational audit that names no anonymous identity can stay.)

---

## Order of execution (once D1/D2 are decided)

1. Move `requireAnonymousIdentityRow` and the resolvers onto `identity_pub`,
   with the controller verifying a PoP per request and passing the proven key
   down instead of the session. Posts/germ inherit it.
2. Resolve D1 (badges) and D2 (ledger) per the decisions above.
3. Stop writing `session_id` and the server `nullifier_secret_hash` on create.
4. Backfill/settle: existing rows either get their `identity_pub` stamped
   (client re-links via `linkRegisteredKey`) or age out.
5. **Last:** drop the `session_id` FK and column from `anonymous_identities`,
   and re-point the anti-linkage test to assert its absence.

Each step is independently shippable and reversible except step 5, which is the
irreversible one and runs only after 1–4 are proven.
