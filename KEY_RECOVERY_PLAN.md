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

Signing and verification are split across two interfaces in
`src/services/issuerKeyStore.ts`. The split exists precisely so a KMS can be
dropped in: a KMS never releases private key material, so no caller may ever
receive a private key.

- **`IssuerSigner`** — the signing seam. Async by construction, because a KMS
  signature is a network call.
  - `getInfo(): Promise<{ did, keyId, publicKeyPem }>` — public metadata only.
  - `sign(payload: Uint8Array): Promise<Uint8Array>` — the signature itself.
    The implementation performs the operation; it does not hand back a key.
- **`IssuerKeyStore`** — the verification seam. Public key material only.
  - `getTrustedVerificationKeys()` — current + previous, if not expired.
  - `getAllVerificationKeys()` — including revoked/expired, for metadata and audit.
  - `currentKeyId()` — the current KMS key version/resource ID.

Steps:

1. Implement `IssuerSigner` against your target KMS (GCP Cloud KMS, AWS KMS,
   HashiCorp Vault, HSM, etc.), mapping `sign()` onto the KMS Sign API for the
   Ed25519 key version.
2. Implement `IssuerKeyStore` to serve cached public keys fetched from the KMS.
3. Return the KMS-backed implementations from `getSharedIssuerSigner()` and
   `getSharedIssuerKeyStore()`.
4. Rotation becomes a KMS key version rotation; `PREVIOUS` logic stays the same.
5. Keep `EnvIssuerSigner` / `EnvIssuerKeyStore` as a local fallback for
   development and disaster recovery testing.

`tests/unit/issuer-signer.test.ts` guards this contract: it asserts no private
key material is reachable through the `IssuerSigner` surface. If that test
fails, a KMS adapter can no longer satisfy the interface.

Note: the *user's* wallet key (`createDemoWalletPresentation`) is deliberately
outside this boundary. It belongs to the subject, not the issuer, and must
never be custodied server-side — in production it lives on the user's device
(see `docs/IDENTITY_DERIVATION.md`).
