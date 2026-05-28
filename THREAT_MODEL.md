# Muvis — Threat Model

## Assets

| Asset | Sensitivity | Storage |
|-------|-------------|---------|
| Issuer private key (Ed25519) | Critical | Env var / future KMS; never in DB |
| Issuer previous public key | High | Env var; verification-only, time-bounded |
| Commitments (Poseidon hashes) | High | SQLite `proof_artifacts.commitment` |
| Revocation hashes | High | SQLite `proof_artifacts.revocation_hash` |
| Sessions & JWTs | High | SQLite `sessions`; client-held access tokens |
| Proof artifacts (ZK claims) | High | SQLite `proof_artifacts` |
| Client salts | Critical | **Never stored by server** (client-side only) |
| PARA verification records | Medium | SQLite; transient freshness windows |
| GrowthBook flag state | Medium | In-memory; external API fallback |

## Adversaries

| Adversary | Goal | Relevance |
|-----------|------|-----------|
| Fake client | Submit forged ZKP or replay commitment | Mitigated by BN254 commitment validation + duplicate commitment rejection |
| Replay attacker | Reuse a previously valid proof/nullifier | Mitigated by nullifier uniqueness + commitment per-credential binding |
| Malicious verifier | Extract witness data (salt, birthYear) from API | Mitigated by client-side proving; server never sees salt |
| Compromised GrowthBook flag | Force-enable demo/simulated paths in prod | Mitigated by **env-gated** break-glass (`BREAK_GLASS_DEMO_PATHS`) |
| Leaked issuer key | Forge credentials or sign malicious claims | Mitigated by key rotation grace period + immediate revocation procedure |
| Insider / DB exfiltration | Link commitments to real identities | Partially mitigated: DB stores commitment + curp_hash + district_hash, but **not** salt or raw CURP |
| Network attacker | Sniff credentials in transit | TLS in production; no plaintext PII in bodies |

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│  Browser / Client Device (prover runs here)                 │
│  • Salt never leaves device                                 │
│  • ZKP generated client-side                                │
└──────────────────────┬──────────────────────────────────────┘
                       │ TLS
┌──────────────────────▼──────────────────────────────────────┐
│  M8 API (AdonisJS)                                          │
│  • Validates commitments (BN254 field check)                │
│  • Issues signed credentials                                │
│  • Enforces rate limits + abuse monitoring                  │
│  • Demo paths gated by flag + env + break-glass             │
└──────┬─────────────────────┬────────────────────────────────┘
       │                     │
┌──────▼──────┐    ┌─────────▼──────────┐
│  SQLite DB  │    │  GrowthBook        │
│  (WAL mode) │    │  (feature flags)   │
│  Local file │    │  External API      │
└─────────────┘    └────────────────────┘
       │
┌──────▼──────────────────────────────────────────────────────┐
│  PARA Trust Network                                         │
│  • Live verification API                                    │
│  • Fallback to local policy only when explicitly allowed    │
└─────────────────────────────────────────────────────────────┘
```

## Hard Guarantees vs Best-Effort Controls

### Hard Guarantees
- **Salt never touches server**: Client generates salt via CSPRNG; server only sees the Poseidon commitment.
- **Commitment in BN254 field**: Server rejects commitments ≤ 0 or ≥ field modulus.
- **Duplicate commitment rejection**: 409 conflict if commitment is already active.
- **Nullifier uniqueness**: One nullifier per (salt, communityId) pair enforced in DB.
- **Issuer key rotation**: Previous key is verification-only and auto-expires.
- **Demo path lockout**: Demo/simulated/dev paths require both GrowthBook flag **and** (`non-production env` or explicit break-glass env). A flag alone cannot open them in production.

### Best-Effort Controls
- **Rate limiting**: In-memory per-IP; effective against casual abuse, not distributed attacks. **Single-process only** — does not share state across PM2 workers or container replicas.
- **Abuse monitoring**: Local buffer + structured logs; requires external SIEM for actionable alerting.
- **CORS allowlist**: Enforced at edge, but client-side bypass is possible.
- **Security headers**: Defense in depth; does not stop determined attackers.
- **GrowthBook flags**: Operational convenience, **not** authorization. Break-glass env is the real gate.

## Known Gaps & Next Steps

1. **KMS integration**: Issuer key currently lives in env vars. Move to GCP/AWS KMS or HashiCorp Vault.
2. **External abuse pipeline**: Local buffer is not production monitoring. Ship to external logs with retention policy.
3. **PARA replay/downgrade protection**: Add challenge/nonce binding between PARA session and M8 credential issuance.
4. **DB encryption at rest**: SQLite file is plaintext. Consider SQLCipher or filesystem encryption.
5. **Distributed rate limiting**: Current in-memory `Map` will not work across PM2 clusters or horizontal replicas. Migrate to Redis-backed limiter before multi-instance deployment.
