# M8 ↔ PARA Integration Contract

## Scope

This document defines the trust boundary and data contract between the Muvis and the PARA verification network.

## What PARA Verifies

PARA is the authoritative source for:
- **Public figure status** (`is_verified_public_figure`)
- **Identity verification** (`has_para_verification`)
- **Party affiliation** (`has_party_affiliation_match`)

PARA does **not** verify:
- Age eligibility (M8 does this via client-side ZKP + INE credential)
- Backup coverage (M8 checks PDS state directly)
- Device trust (M8 manages its own device trust graph)

## What M8 Verifies

M8 is responsible for:
- **Client-side ZKP validation** (Groth16 proof verification, BN254 field checks)
- **Duplicate commitment prevention** (one active commitment per identity)
- **Credential issuance and revocation** (Ed25519 signatures, CRL)
- **Session binding** (OAuth → DID → anonymous profile)
- **Nullifier uniqueness** (one vote/participation per community)

## Identifiers That Cross the Boundary

```
M8                              PARA
─────────────────────────────────────────────────────────────
session.did  ─────────────────► actor handle / DID
session.handle ───────────────► actor handle
proof_artifacts.reference ────► para:<handle> or para:<did>
```

- **No salt crosses the boundary.** Salts never leave the client device.
- **No raw CURP crosses the boundary.** Only `curp_hash` (sha256, truncated) is stored by M8.
- **No raw address crosses the boundary.** Only `district_hash` is stored by M8.

## Persistence Split

| Data | Persisted By | Notes |
|------|-------------|-------|
| PARA verification record | PARA | Source of truth; M8 caches only the outcome |
| ZKP proof | Client only | Server verifies, then discards the proof object |
| Commitment | M8 | Stored in `proof_artifacts`; linked to session |
| Credential signature | M8 | Ed25519 signed by M8 issuer key |
| Revocation hash | M8 | Stored in DB; also returned inside the credential object |
| Session tokens | M8 | JWT access/refresh tokens |

## Failure Modes

### PARA API Unavailable
1. M8 attempts live PARA API call with timeout (`PARA_API_TIMEOUT_MS`).
2. If live call fails:
   - If `LocalParaFallbackEnable` is **on** (dev/demo only): use deterministic local fallback.
   - If **off**: return `disposition: 'unavailable'` or `disposition: 'not-verified'`.
3. M8 must **never** silently downgrade a live PARA failure to a positive local result in production.

### PARA API Returns Stale Data
- M8 checks `evaluatedAt` against the `ParaTrustContract` freshness policy per record type.
- If freshness is exceeded, M8 treats the result as invalid and requests re-verification.

### M8-PARA Session Mismatch
- M8 binds the PARA verification to the OAuth session DID.
- If the client presents a PARA result for a different DID, M8 rejects with `issuer_not_trusted`.

## Replay / Downgrade Protection

### Replay Attack (reusing an old verification)
**Threat**: An attacker captures a valid PARA verification response and replays it to obtain a fresh M8 credential.

**Mitigation**:
1. M8 generates a per-session `issuanceChallenge` (random 256-bit nonce) stored in the session row.
2. The client must include the challenge hash in the ZKP public signals or in the credential request payload.
3. M8 validates that the challenge matches the current session before issuing the credential.
4. Challenges are single-use and rotated after each credential issuance attempt.

### Downgrade Attack (forcing local fallback)
**Threat**: An attacker disrupts the PARA API to force M8 into local fallback mode, then exploits the weaker local logic.

**Mitigation**:
1. `LocalParaFallbackEnable` is gated by `assertDemoPathAllowed` — it cannot activate in production unless break-glass is explicitly enabled.
2. In production, PARA unavailability results in a hard failure (`unavailable`), not a silent fallback.

## Trust Boundary Summary

```
┌─────────────────────────────────────────────────────────────┐
│  Client (Browser)                                           │
│  • Generates salt + ZKP                                     │
│  • Stores credential + revocationHash                       │
│  • Presents wallet proofs                                   │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTPS
┌──────────────────────▼──────────────────────────────────────┐
│  M8 API                                                     │
│  • Validates ZKP + commitments                              │
│  • Queries PARA (live API)                                  │
│  • Issues / revokes credentials                             │
│  • Enforces rate limits + abuse monitoring                  │
└──────┬─────────────────────┬────────────────────────────────┘
       │                     │
┌──────▼──────┐    ┌─────────▼──────────┐
│  SQLite DB  │    │  PARA Network      │
│  (local)    │    │  (external API)    │
└─────────────┘    └────────────────────┘
```

## Operational Invariants

1. **No demo path in prod without break-glass.** `SimulatedIneEnable`, `LocalParaFallbackEnable`, `LocalTrustPolicyEnable`, etc. are all gated by `assertDemoPathAllowed`.
2. **Freshness-checked.** Every PARA result carries `evaluatedAt`; M8 enforces per-record-type staleness windows.
3. **Revocable.** Credentials can be revoked via `revocationHash`; CRL is public.
4. **Non-repudiable.** Credentials are Ed25519 signed; the issuer key is durable and rotatable.
