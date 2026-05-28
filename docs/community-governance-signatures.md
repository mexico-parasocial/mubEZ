# Community Governance Vote Signatures

Closed-beta community votes are counted only after the server verifies an
Ed25519 signature from the voting admin DID. Votes are final: one admin DID can
cast one vote per action, and the vote cannot be changed after submission.

## Canonical Payload

Build this object with exactly this key order, then `JSON.stringify` it without
extra formatting:

```json
{
  "type": "app.m8.community.vote",
  "version": 1,
  "communityId": "community-...",
  "actionId": "action-...",
  "actionType": "blog_post",
  "payloadHash": "sha256:<base64url-sha256-of-canonical-action-payload>",
  "adminDid": "did:plc:...",
  "vote": "approve",
  "signedAt": "2026-05-27T16:00:00.000Z",
  "nonce": "<128-bit-base64url>"
}
```

`payloadHash` is SHA-256 over the action payload encoded as canonical JSON:
object keys sorted lexicographically, arrays in order, and primitive values as
standard JSON.

## Signature Request

Submit the vote as:

```json
{
  "vote": "approve",
  "signature": "<ed25519-signature-base64url>",
  "signedAt": "2026-05-27T16:00:00.000Z",
  "nonce": "<128-bit-base64url>",
  "keyId": "did:plc:...#key-1"
}
```

`keyId` is optional. If provided, it must identify a DID document key referenced
by `assertionMethod` or `authentication`. Keys that only appear as bare
`verificationMethod` entries are not accepted for voting.

## Phase B Requirement

Before public beta, governance needs an admin recovery mechanism and a TTL or
explicit expiration process for pending actions.
