# Muvis — Key Recovery Plan

This document covers issuer key lifecycle: normal rotation, emergency compromise, total loss recovery, and future KMS migration.

## 1. Normal Rotation

1. Generate a new Ed25519 keypair.
2. Set `IDENTITY_ISSUER_PRIVATE_JWK`, `IDENTITY_ISSUER_PUBLIC_JWK`, and `IDENTITY_ISSUER_KEY_ID` to the new key.
3. Move the **old public JWK** to `IDENTITY_ISSUER_PREVIOUS_PUBLIC_JWK` and its key ID to `IDENTITY_ISSUER_PREVIOUS_KEY_ID`.
4. Set `IDENTITY_ISSUER_PREVIOUS_KEY_EXPIRES_AT` to a future ISO datetime (recommended: 7–30 days).
5. Deploy.
6. Credentials signed with the old key continue to verify until the expiry datetime is reached.
7. After the grace period, remove `IDENTITY_ISSUER_PREVIOUS_PUBLIC_JWK`, `IDENTITY_ISSUER_PREVIOUS_KEY_ID`, and `IDENTITY_ISSUER_PREVIOUS_KEY_EXPIRES_AT`.

**Rules:**
- The previous key is **verification-only**. It is never used to sign new credentials.
- The previous key is **time-bounded**. After `EXPIRES_AT`, verification trust is removed automatically.

## 2. Emergency Compromise

1. Immediately revoke all credentials signed by the compromised key (update `proof_artifacts.status` to `revoked`).
2. Push a CRL update so relying parties reject the revoked credentials.
3. Rotate to a new keypair (follow normal rotation steps 1–5).
4. Do **not** set the compromised key as `PREVIOUS` — it must not be trusted.
5. Notify all relying parties to drop the compromised public key from their trust anchors.

## 3. Recovery from Total Loss

If the current private key is lost without a backup:
1. Generate a new keypair.
2. Set it as the current signing key.
3. Re-issue all active credentials. This requires user re-verification (INE scan, face match, etc.).
4. There is no magic recovery path for Ed25519 private keys — plan backups accordingly.

## 4. KMS Migration Path

1. Implement `IssuerKeyStore` adapter for your target KMS (GCP Cloud KMS, AWS KMS, HashiCorp Vault, HSM, etc.).
2. The adapter implements:
   - `getSigningKey()` — calls KMS to sign a digest, returns the public key material.
   - `getTrustedVerificationKeys()` — returns cached public keys (current + previous).
   - `currentKeyId()` — returns the current KMS key version/resource ID.
3. Replace `EnvIssuerKeyStore` with the KMS adapter in `getSharedIssuerKeyStore()`.
4. Rotation becomes a KMS key version rotation; `PREVIOUS` logic stays the same.
5. Keep `EnvIssuerKeyStore` as a local fallback for development and disaster recovery testing.
