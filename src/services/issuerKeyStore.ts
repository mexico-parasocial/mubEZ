import { createPrivateKey, createPublicKey, type KeyObject } from 'node:crypto'

export interface IssuerVerificationKey {
  did: string
  keyId: string
  publicKeyPem: string
  status: 'active' | 'previous' | 'revoked' | 'expired'
  notAfter?: string
}

export interface IssuerSigningKey {
  did: string
  keyId: string
  publicKeyPem: string
  privateKey: KeyObject
}

export interface IssuerKeyStore {
  /** Current signing key. Throws if not configured. */
  getSigningKey(): IssuerSigningKey
  /** All keys that should be trusted for verification (current + previous, if not expired). */
  getTrustedVerificationKeys(): IssuerVerificationKey[]
  /** All configured public keys, including revoked or expired keys for metadata/audit. */
  getAllVerificationKeys(): IssuerVerificationKey[]
  /** Key ID of the current signing key. */
  currentKeyId(): string
}

type ParsedKeyMaterial = {
  did: string
  keyId: string
  privateKey: KeyObject
  publicKeyPem: string
}

function parseJsonObject(raw: string, label: string) {
  try {
    const parsed = JSON.parse(raw) as unknown
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error(`${label} must be a JSON object`)
    }
    return parsed as Record<string, unknown>
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    throw new Error(`${label} is invalid: ${message}`)
  }
}

function loadCurrentKeyFromEnv(): ParsedKeyMaterial | null {
  const hasAny = Boolean(
    process.env.IDENTITY_ISSUER_DID || process.env.IDENTITY_ISSUER_PRIVATE_JWK || process.env.IDENTITY_ISSUER_PUBLIC_JWK || process.env.IDENTITY_ISSUER_KEY_ID
  )

  if (!hasAny) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error(
        'IDENTITY_ISSUER_DID, IDENTITY_ISSUER_PRIVATE_JWK, and IDENTITY_ISSUER_PUBLIC_JWK are required in production'
      )
    }
    return null
  }

  if (!process.env.IDENTITY_ISSUER_DID || !process.env.IDENTITY_ISSUER_PRIVATE_JWK || !process.env.IDENTITY_ISSUER_PUBLIC_JWK) {
    throw new Error(
      'IDENTITY_ISSUER_DID, IDENTITY_ISSUER_PRIVATE_JWK, and IDENTITY_ISSUER_PUBLIC_JWK must be provided together'
    )
  }

  const privateJwk = parseJsonObject(process.env.IDENTITY_ISSUER_PRIVATE_JWK, 'IDENTITY_ISSUER_PRIVATE_JWK')
  const publicJwk = parseJsonObject(process.env.IDENTITY_ISSUER_PUBLIC_JWK, 'IDENTITY_ISSUER_PUBLIC_JWK')
  const privateKey = createPrivateKey({ key: privateJwk, format: 'jwk' })
  const publicKey = createPublicKey({ key: publicJwk, format: 'jwk' })
  const derivedPublicKey = createPublicKey(privateKey)

  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  const derivedPublicKeyPem = derivedPublicKey.export({ type: 'spki', format: 'pem' }).toString()
  if (publicKeyPem !== derivedPublicKeyPem) {
    throw new Error('IDENTITY_ISSUER_PUBLIC_JWK does not match IDENTITY_ISSUER_PRIVATE_JWK')
  }

  return {
    did: process.env.IDENTITY_ISSUER_DID,
    keyId: process.env.IDENTITY_ISSUER_KEY_ID ?? `${process.env.IDENTITY_ISSUER_DID}#ed25519`,
    privateKey,
    publicKeyPem,
  }
}

function loadPreviousKeyFromEnv(): Omit<ParsedKeyMaterial, 'privateKey'> | null {
  if (!process.env.IDENTITY_ISSUER_PREVIOUS_PUBLIC_JWK) return null
  const publicJwk = parseJsonObject(process.env.IDENTITY_ISSUER_PREVIOUS_PUBLIC_JWK, 'IDENTITY_ISSUER_PREVIOUS_PUBLIC_JWK')
  const publicKey = createPublicKey({ key: publicJwk, format: 'jwk' })
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  return {
    did: process.env.IDENTITY_ISSUER_DID ?? 'did:m8:ine:unknown',
    keyId: process.env.IDENTITY_ISSUER_PREVIOUS_KEY_ID ?? `${process.env.IDENTITY_ISSUER_DID ?? 'did:m8:ine:unknown'}#previous-ed25519`,
    publicKeyPem,
  }
}

function loadRevokedKeyIdsFromEnv(): Set<string> {
  return new Set(
    (process.env.IDENTITY_ISSUER_REVOKED_KEY_IDS ?? '')
      .split(',')
      .map((keyId) => keyId.trim())
      .filter(Boolean)
  )
}

export class EnvIssuerKeyStore implements IssuerKeyStore {
  private _current: ParsedKeyMaterial | null = null
  private _previous: Omit<ParsedKeyMaterial, 'privateKey'> | null = null
  private _revokedKeyIds = new Set<string>()

  constructor() {
    this._current = loadCurrentKeyFromEnv()
    this._previous = loadPreviousKeyFromEnv()
    this._revokedKeyIds = loadRevokedKeyIdsFromEnv()

    if (this._current && this._revokedKeyIds.has(this._current.keyId)) {
      throw new Error(`Current issuer key is revoked: ${this._current.keyId}`)
    }
  }

  getSigningKey(): IssuerSigningKey {
    if (!this._current) {
      throw new Error('No current signing key is configured')
    }
    return this._current
  }

  getTrustedVerificationKeys(): IssuerVerificationKey[] {
    return this.getAllVerificationKeys().filter((key) =>
      key.status === 'active' || key.status === 'previous'
    )
  }

  getAllVerificationKeys(): IssuerVerificationKey[] {
    const keys: IssuerVerificationKey[] = []
    if (this._current) {
      keys.push({
        did: this._current.did,
        keyId: this._current.keyId,
        publicKeyPem: this._current.publicKeyPem,
        status: this._revokedKeyIds.has(this._current.keyId) ? 'revoked' : 'active',
      })
    }
    if (this._previous) {
      const expired = this._isPreviousExpired()
      const status = this._revokedKeyIds.has(this._previous.keyId)
        ? 'revoked'
        : expired
          ? 'expired'
          : 'previous'
      keys.push({
        did: this._previous.did,
        keyId: this._previous.keyId,
        publicKeyPem: this._previous.publicKeyPem,
        status,
        notAfter: process.env.IDENTITY_ISSUER_PREVIOUS_KEY_EXPIRES_AT,
      })
    }
    return keys
  }

  currentKeyId(): string {
    return this._current?.keyId ?? ''
  }

  private _isPreviousExpired(): boolean {
    if (!process.env.IDENTITY_ISSUER_PREVIOUS_KEY_EXPIRES_AT) return false
    const expires = new Date(process.env.IDENTITY_ISSUER_PREVIOUS_KEY_EXPIRES_AT)
    return Number.isNaN(expires.getTime()) ? false : new Date() > expires
  }
}

/** Shared singleton instance. */
let _sharedStore: EnvIssuerKeyStore | null = null

export function getSharedIssuerKeyStore(): EnvIssuerKeyStore {
  if (!_sharedStore) {
    _sharedStore = new EnvIssuerKeyStore()
  }
  return _sharedStore
}

/** Reset the shared singleton (useful in tests). */
export function resetSharedIssuerKeyStore(): void {
  _sharedStore = null
}
