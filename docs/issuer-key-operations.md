# Issuer Key Operations

M8 issuer keys are production trust anchors. Treat the private JWK like a signing
certificate private key: it must live in a secret manager, not in source control,
Docker images, screenshots, tickets, or shared `.env` files.

## Generate A New Issuer Key

```bash
npm run keys:generate -- did:m8:ine:emisor-001 ine-ed25519-2026-05-23
```

The command prints:

- `IDENTITY_ISSUER_DID`
- `IDENTITY_ISSUER_KEY_ID`
- `IDENTITY_ISSUER_PRIVATE_JWK`
- `IDENTITY_ISSUER_PUBLIC_JWK`

Put `IDENTITY_ISSUER_PRIVATE_JWK` in the deployment secret manager. The public JWK
and key id may be shared with verifiers.

## Configure The Current Signing Key

Required in production:

```dotenv
IDENTITY_ISSUER_DID=did:m8:ine:emisor-001
IDENTITY_ISSUER_KEY_ID=ine-ed25519-2026-05-23
IDENTITY_ISSUER_PRIVATE_JWK=<secret-manager-value>
IDENTITY_ISSUER_PUBLIC_JWK=<public-jwk>
```

On boot or first issuer use, the service verifies that the public JWK matches the
private JWK. If the current key id appears in `IDENTITY_ISSUER_REVOKED_KEY_IDS`,
the service fails instead of signing credentials with a revoked key.

## Planned Rotation

1. Generate the new key pair.
2. Move the old current public key into `IDENTITY_ISSUER_PREVIOUS_PUBLIC_JWK`.
3. Move the old current key id into `IDENTITY_ISSUER_PREVIOUS_KEY_ID`.
4. Set `IDENTITY_ISSUER_PREVIOUS_KEY_EXPIRES_AT` to the end of the verifier grace period.
5. Set the new current private/public JWK and `IDENTITY_ISSUER_KEY_ID`.
6. Deploy.
7. Check `/v1/issuers`; it should show the new key as `active` and the old key as `previous`.
8. After the grace period, remove the previous-key env vars.

During grace, previous keys verify old credentials but never sign new credentials.

## Compromised Key

1. Add the compromised key id to `IDENTITY_ISSUER_REVOKED_KEY_IDS`.
2. If the current key is compromised, generate and deploy a replacement current key at the same time.
3. Deploy immediately.
4. Check `/v1/issuers`; the compromised key should show `revoked` or disappear from trusted verification.
5. Publish incident details to verifier operators and force re-verification where appropriate.

`IDENTITY_ISSUER_REVOKED_KEY_IDS` is comma-separated:

```dotenv
IDENTITY_ISSUER_REVOKED_KEY_IDS=ine-ed25519-2026-01,ine-ed25519-2026-03
```

## Audit Expectations

Every credential issuance ledger entry must include:

- `credentialId`
- `issuerDid`
- `issuerKeyId`
- `proofArtifactId` via the ledger target
- `commitment`
- `revocationHash`

That makes post-incident scoping possible: you can identify which credentials
were signed by a compromised key without exposing witness material.
