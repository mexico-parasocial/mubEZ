import {
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto'
import { z } from 'zod'
import env from '#start/env'
import { Features, isFeatureEnabled } from './features.js'
import {
  getSharedIssuerKeyStore,
  getSharedIssuerSigner,
  resetSharedIssuerKeyStore,
  type IssuerSigner,
} from './issuerKeyStore.js'
import type {
  M8IdentityCredential,
  M8IdentityCredentialClaims,
  M8IdentityElementId,
  M8IdentityRequest,
  M8IdentityRequestInput,
  M8IdentityVerificationResult,
  M8TrustedIssuer,
  M8WalletPresentation,
} from '../types/index.js'

const DEFAULT_MERCHANT_IDENTIFIER = 'merchant.m8.identity.dev'
const DEFAULT_REQUEST_TTL_SECONDS = 5 * 60
const PRESENTATION_TTL_SECONDS = 90
const DEMO_ISSUER_DID = 'did:m8:ine:emisor-001'
const DEMO_ISSUER_KEY_ID = 'demo-ine-ed25519'

let _ineIssuerKey: ReturnType<typeof generateKeyPairSync> | null = null
let _demoWalletKey: ReturnType<typeof generateKeyPairSync> | null = null

/*
 * Public issuer metadata. Private key material never leaves the
 * IssuerSigner boundary (see issuerKeyStore.ts).
 */
type SigningIssuer = {
  did: string
  keyId: string
  name: string
  publicKeyPem: string
}

function loadConfiguredIssuer() {
  try {
    const store = getSharedIssuerKeyStore()
    const key = store.getSigningKey()
    return {
      did: key.did,
      keyId: key.keyId,
      publicKeyPem: key.publicKeyPem,
    }
  } catch (error) {
    if (env.get('NODE_ENV') === 'production') {
      throw error
    }
    return null
  }
}

export function assertIssuerKeyConfiguration() {
  loadConfiguredIssuer()
}

function getDemoIneIssuerKey() {
  if (!isFeatureEnabled(Features.DemoIdentityWalletEnable)) {
    throw new Error('Demo identity issuer key is disabled')
  }
  if (!_ineIssuerKey) {
    _ineIssuerKey = generateKeyPairSync('ed25519')
  }
  return _ineIssuerKey
}

function getDemoWalletKey() {
  if (!isFeatureEnabled(Features.DemoIdentityWalletEnable)) {
    throw new Error('Demo identity wallet is disabled')
  }
  if (!_demoWalletKey) {
    _demoWalletKey = generateKeyPairSync('ed25519')
  }
  return _demoWalletKey
}

function getSigningIssuer(): SigningIssuer {
  const configuredIssuer = loadConfiguredIssuer()
  if (configuredIssuer) {
    return {
      did: configuredIssuer.did,
      keyId: configuredIssuer.keyId,
      name: 'Instituto Nacional Electoral',
      publicKeyPem: configuredIssuer.publicKeyPem,
    }
  }

  const demoIssuer = getDemoIneIssuerKey()
  return {
    did: DEMO_ISSUER_DID,
    keyId: DEMO_ISSUER_KEY_ID,
    name: 'Instituto Nacional Electoral',
    publicKeyPem: demoIssuer.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  }
}

/** The signer used for credential issuance: configured key if present, demo key otherwise (dev only). */
function getIssuerSigner(): IssuerSigner {
  if (loadConfiguredIssuer()) {
    return getSharedIssuerSigner()
  }
  const demoIssuer = getDemoIneIssuerKey()
  return {
    async getInfo() {
      return {
        did: DEMO_ISSUER_DID,
        keyId: DEMO_ISSUER_KEY_ID,
        publicKeyPem: demoIssuer.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      }
    },
    async sign(payload: Uint8Array) {
      return sign(null, Buffer.from(payload), demoIssuer.privateKey)
    },
  }
}

export function getTrustedIssuers(): M8TrustedIssuer[] {
  const store = getSharedIssuerKeyStore()
  const verificationKeys = store.getTrustedVerificationKeys()
  const signingIssuer = getSigningIssuer()

  const issuers: M8TrustedIssuer[] = verificationKeys.map((key, index) => ({
    did: key.did,
    keyId: key.keyId,
    name: index === 0 ? 'Instituto Nacional Electoral' : 'Instituto Nacional Electoral (previous)',
    country: 'MX',
    status: key.status,
    notAfter: key.notAfter,
    publicKeyPem: key.publicKeyPem,
    allowedElements: ['age_over_18', 'age_over_21', 'citizenship', 'district_hash', 'curp_hash'],
  }))

  if (issuers.length === 0) {
    issuers.push({
      did: signingIssuer.did,
      keyId: signingIssuer.keyId,
      name: signingIssuer.name,
      country: 'MX',
      status: 'active',
      publicKeyPem: signingIssuer.publicKeyPem,
      allowedElements: ['age_over_18', 'age_over_21', 'citizenship', 'district_hash', 'curp_hash'],
    })
  }

  issuers.push({
    did: 'did:m8:renapo:emisor-001',
    keyId: 'renapo-suspended',
    name: 'RENAPO',
    country: 'MX',
    status: 'suspended',
    publicKeyPem: signingIssuer.publicKeyPem,
    allowedElements: ['citizenship', 'curp_hash'],
  })

  return issuers
}

export function getIssuerMetadata(): M8TrustedIssuer[] {
  const store = getSharedIssuerKeyStore()
  const signingIssuer = getSigningIssuer()
  const issuerKeys = store.getAllVerificationKeys()
  const issuers = issuerKeys.map((key, index) => ({
    did: key.did,
    keyId: key.keyId,
    name: index === 0 ? 'Instituto Nacional Electoral' : 'Instituto Nacional Electoral (previous)',
    country: 'MX',
    status: key.status,
    notAfter: key.notAfter,
    publicKeyPem: key.publicKeyPem,
    allowedElements: ['age_over_18', 'age_over_21', 'citizenship', 'district_hash', 'curp_hash'],
  })) satisfies M8TrustedIssuer[]

  if (issuers.length > 0) {
    return issuers
  }

  return [
    {
      did: signingIssuer.did,
      keyId: signingIssuer.keyId,
      name: signingIssuer.name,
      country: 'MX',
      status: 'active',
      publicKeyPem: signingIssuer.publicKeyPem,
      allowedElements: ['age_over_18', 'age_over_21', 'citizenship', 'district_hash', 'curp_hash'],
    },
  ]
}

export { resetSharedIssuerKeyStore }

function nowIso() {
  return new Date().toISOString()
}

function addSeconds(seconds: number) {
  return new Date(Date.now() + seconds * 1000).toISOString()
}

function base64url(value: Buffer) {
  return value.toString('base64url')
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`

  return `{${Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, entry]) => `${JSON.stringify(key)}:${stableJson(entry)}`)
    .join(',')}}`
}

function signedCredentialPayload(credential: Omit<M8IdentityCredential, 'signature'>) {
  const payload: Record<string, unknown> = {
    id: credential.id,
    issuerDid: credential.issuerDid,
    issuerKeyId: credential.issuerKeyId,
    subjectDid: credential.subjectDid,
    issuedAt: credential.issuedAt,
    expiresAt: credential.expiresAt,
    claims: credential.claims,
    revocationHash: credential.revocationHash,
    signatureAlg: credential.signatureAlg,
  }
  // Omitted rather than null so credentials issued before holder binding keep
  // verifying; adding a holder key to one of them breaks its signature.
  if (credential.holderPublicKey !== undefined) {
    payload.holderPublicKey = credential.holderPublicKey
  }
  return stableJson(payload)
}

function signedPresentationPayload(presentation: Omit<M8WalletPresentation, 'signature'>) {
  return stableJson(presentation)
}

function signPayload(payload: string, privateKey: KeyObject) {
  return base64url(sign(null, Buffer.from(payload), privateKey))
}

function verifyPayload(payload: string, signature: string, publicKey: string | KeyObject) {
  try {
    return verify(null, Buffer.from(payload), publicKey, Buffer.from(signature, 'base64url'))
  } catch {
    return false
  }
}

/** Parses an Ed25519 SPKI PEM public key; null for anything else. */
export function parseHolderPublicKey(pem: unknown): KeyObject | null {
  if (typeof pem !== 'string' || pem.length > 1024) return null
  try {
    const key = createPublicKey({ key: pem, format: 'pem', type: 'spki' })
    return key.asymmetricKeyType === 'ed25519' ? key : null
  } catch {
    return null
  }
}

/**
 * What a wallet signs at issuance to prove it holds the key it asks the
 * issuer to bind. The issuance challenge is single-use and session-scoped.
 */
export function holderBindingMessage(issuanceChallenge: string) {
  return `m8.identity.holder-binding.v1:${issuanceChallenge}`
}

export function verifyHolderKeyProof(holderPublicKey: string, issuanceChallenge: string, proof: string) {
  const key = parseHolderPublicKey(holderPublicKey)
  if (!key) return false
  return verifyPayload(holderBindingMessage(issuanceChallenge), proof, key)
}

function validateRequestedElements(elements: M8IdentityRequestInput['requestedElements']) {
  if (!Array.isArray(elements) || elements.length === 0) {
    throw new Error('requestedElements must contain at least one identity element')
  }

  const seen = new Set<string>()
  for (const element of elements) {
    if (!element?.id || seen.has(element.id)) {
      throw new Error('requestedElements must be unique and include an id')
    }
    seen.add(element.id)

    if (!element.intentToStore?.mode) {
      throw new Error(`intentToStore is required for ${element.id}`)
    }

    if (element.intentToStore.mode === 'may-store' && element.intentToStore.days <= 0) {
      throw new Error(`may-store intent for ${element.id} must include positive days`)
    }
  }
}

export function createIdentityRequest(
  sessionId: string,
  input: M8IdentityRequestInput
): M8IdentityRequest {
  if (!input.audienceAppId?.trim()) throw new Error('audienceAppId is required')
  if (!input.audienceAppName?.trim()) throw new Error('audienceAppName is required')
  if (!input.purpose?.trim()) throw new Error('purpose is required')

  validateRequestedElements(input.requestedElements)

  const ttl = input.expiresInSeconds ?? DEFAULT_REQUEST_TTL_SECONDS
  if (ttl < 30 || ttl > 15 * 60) {
    throw new Error('expiresInSeconds must be between 30 and 900 seconds')
  }

  return {
    id: `identity-request-${randomUUID()}`,
    sessionId,
    nonce: base64url(randomBytes(32)),
    audienceAppId: input.audienceAppId,
    audienceAppName: input.audienceAppName,
    purpose: input.purpose,
    merchantIdentifier: input.merchantIdentifier ?? DEFAULT_MERCHANT_IDENTIFIER,
    requestedElements: input.requestedElements,
    status: 'active',
    createdAt: nowIso(),
    expiresAt: addSeconds(ttl),
    usedAt: null,
  }
}

export async function createIssuerSignedCredential(params: {
  subjectDid: string
  claims: M8IdentityCredentialClaims
  revocationHash: string
  expiresAt?: string
  /**
   * Required: a credential without an issuer-signed holder key cannot be
   * presented, so none is issued. Callers must have verified possession.
   */
  holderPublicKey: string
}): Promise<M8IdentityCredential> {
  if (!parseHolderPublicKey(params.holderPublicKey)) {
    throw new Error('holderPublicKey must be an Ed25519 SPKI PEM public key')
  }
  const signer = getIssuerSigner()
  const issuer = await signer.getInfo()
  const unsignedCredential: Omit<M8IdentityCredential, 'signature'> = {
    id: `credential-${randomUUID()}`,
    issuerDid: issuer.did,
    issuerKeyId: issuer.keyId,
    subjectDid: params.subjectDid,
    issuedAt: nowIso(),
    expiresAt: params.expiresAt ?? addSeconds(365 * 24 * 60 * 60),
    claims: params.claims,
    revocationHash: params.revocationHash,
    holderPublicKey: params.holderPublicKey.trim(),
    signatureAlg: 'Ed25519',
  }

  const payload = signedCredentialPayload(unsignedCredential)
  const signature = await signer.sign(Buffer.from(payload))
  return {
    ...unsignedCredential,
    signature: base64url(Buffer.from(signature)),
  }
}

/**
 * Wallet side: signs a full-credential presentation of `credential` for
 * `request` with the holder's private key. Every claim in the credential
 * reaches the verifier; `disclosedClaimIds` only names which ones the holder
 * asserts for this request.
 */
export function signWalletPresentation(params: {
  request: Pick<M8IdentityRequest, 'id' | 'nonce' | 'audienceAppId'>
  credential: M8IdentityCredential
  disclosedClaimIds: M8IdentityElementId[]
  holderPrivateKey: KeyObject
}): M8WalletPresentation {
  const disclosedClaims = Object.fromEntries(
    params.disclosedClaimIds
      .filter((id) => Object.hasOwn(params.credential.claims, id))
      .map((id) => [id, params.credential.claims[id]])
  ) as M8IdentityCredentialClaims

  const unsignedPresentation: Omit<M8WalletPresentation, 'signature'> = {
    type: PRESENTATION_TYPE,
    disclosure: 'full-credential',
    requestId: params.request.id,
    nonce: params.request.nonce,
    audienceAppId: params.request.audienceAppId,
    credential: params.credential,
    disclosedClaims,
    issuedAt: nowIso(),
    expiresAt: addSeconds(PRESENTATION_TTL_SECONDS),
    signatureAlg: 'Ed25519',
  }

  return {
    ...unsignedPresentation,
    signature: signPayload(signedPresentationPayload(unsignedPresentation), params.holderPrivateKey),
  }
}

export async function createDemoWalletPresentation(params: {
  request: M8IdentityRequest
  subjectDid: string
  selectedElementIds?: M8IdentityElementId[]
}): Promise<M8WalletPresentation> {
  const selected = new Set(
    params.selectedElementIds ?? params.request.requestedElements.map((element) => element.id)
  )
  const demoClaims: M8IdentityCredentialClaims = {
    age_over_18: true,
    age_over_21: true,
    citizenship: 'MX',
    district_hash: 'sha256:district:mx-jal-10',
    curp_hash: 'sha256:curp:redacted-demo',
  }
  /*
   * Full-credential disclosure reveals every claim the credential holds, so
   * the demo issuer mints a credential holding only the selected claims. This
   * is issuance, signed over exactly these claims — not redaction of a signed
   * credential, which would break its signature.
   */
  const claims = Object.fromEntries(
    Object.entries(demoClaims).filter(([key]) => selected.has(key as M8IdentityElementId))
  ) as M8IdentityCredentialClaims

  const walletKey = getDemoWalletKey()
  const credential = await createIssuerSignedCredential({
    subjectDid: params.subjectDid,
    claims,
    revocationHash: base64url(randomBytes(32)),
    holderPublicKey: walletKey.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  })

  return signWalletPresentation({
    request: params.request,
    credential,
    disclosedClaimIds: Object.keys(claims) as M8IdentityElementId[],
    holderPrivateKey: walletKey.privateKey,
  })
}

// ─── Verification ──────────────────────────────────────────────────────────

const PRESENTATION_TYPE = 'm8.identity.presentation.v2' as const
const LEGACY_PRESENTATION_TYPE = 'm8.identity.presentation.v1'
const CLOCK_SKEW_MS = 60 * 1000
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/

/**
 * Identifiers that link a presentation to a person across verifiers. Under
 * full-credential disclosure they cannot be withheld, so a credential that
 * carries one may only be presented to a request that asked for it.
 */
export const LINKABLE_IDENTITY_ELEMENTS: readonly M8IdentityElementId[] = ['curp_hash', 'district_hash']

/**
 * Claims for the data-minimized credential issued next to the full one: no
 * linkable identifier, and only claims that assert something proven (an
 * unproven `age_over_21: false` is left out rather than disclosed).
 */
export function minimizedCredentialClaims(claims: M8IdentityCredentialClaims): M8IdentityCredentialClaims {
  return Object.fromEntries(
    Object.entries(claims).filter(([id, value]) =>
      !LINKABLE_IDENTITY_ELEMENTS.includes(id as M8IdentityElementId) && value !== false && value !== undefined
    )
  ) as M8IdentityCredentialClaims
}

const isoInstant = z.string().regex(ISO_INSTANT)
const claimsSchema = z.object({
  age_over_18: z.boolean().optional(),
  age_over_21: z.boolean().optional(),
  citizenship: z.string().min(1).max(256).optional(),
  district_hash: z.string().min(1).max(256).optional(),
  curp_hash: z.string().min(1).max(256).optional(),
  verified_public_figure: z.boolean().optional(),
}).strict()

const credentialSchema = z.object({
  id: z.string().min(1),
  issuerDid: z.string().min(1),
  issuerKeyId: z.string().min(1),
  subjectDid: z.string().min(1),
  issuedAt: isoInstant,
  expiresAt: isoInstant,
  claims: claimsSchema,
  revocationHash: z.string().min(1),
  holderPublicKey: z.string().min(1).optional(),
  signatureAlg: z.literal('Ed25519'),
  signature: z.string().min(1),
}).strict()

const presentationSchema = z.object({
  type: z.literal(PRESENTATION_TYPE),
  disclosure: z.literal('full-credential'),
  requestId: z.string().min(1),
  nonce: z.string().min(1),
  audienceAppId: z.string().min(1),
  credential: credentialSchema,
  disclosedClaims: claimsSchema,
  issuedAt: isoInstant,
  expiresAt: isoInstant,
  signatureAlg: z.literal('Ed25519'),
  signature: z.string().min(1),
}).strict()

export type CredentialRevocationStatus = 'active' | 'pending' | 'revoked' | 'suspended' | 'expired' | 'unknown'

export type PresentationVerificationOptions = {
  /** DID of the session the request belongs to; the credential subject must match it. */
  expectedSubjectDid: string
  trustedIssuers?: M8TrustedIssuer[]
  /** Status of the credential's revocationHash in the issuer's registry. */
  revocationStatus: (revocationHash: string) => CredentialRevocationStatus
  /** Reject credentials the registry does not know. Default true. */
  rejectUnknownRevocationStatus?: boolean
  /** Verification instant in ms since epoch; defaults to now (test vectors pin it). */
  now?: number
}

function invalidResult(
  request: M8IdentityRequest,
  errors: string[],
  checkedAt: string,
): M8IdentityVerificationResult {
  return {
    valid: false,
    requestId: request.id,
    presentationId: '',
    issuerDid: null,
    issuerName: null,
    subjectDid: null,
    disclosedClaims: {},
    disclosure: 'full-credential',
    revealedClaimIds: [],
    checkedAt,
    errors,
    warnings: [],
  }
}

export function verifyWalletPresentation(
  request: M8IdentityRequest,
  input: unknown,
  options: PresentationVerificationOptions,
): M8IdentityVerificationResult {
  const errors: string[] = []
  const warnings: string[] = []
  const now = options.now ?? Date.now()
  const checkedAt = new Date(now).toISOString()

  if ((input as { type?: unknown } | null)?.type === LEGACY_PRESENTATION_TYPE) {
    return invalidResult(request, [
      `${LEGACY_PRESENTATION_TYPE} is not accepted: it has no issuer-signed holder key; present a ${PRESENTATION_TYPE} credential`,
    ], checkedAt)
  }
  const parsed = presentationSchema.safeParse(input)
  if (!parsed.success) {
    return invalidResult(
      request,
      parsed.error.issues.map((issue) => `malformed presentation: ${issue.path.join('.') || '(root)'}: ${issue.message}`),
      checkedAt,
    )
  }
  const presentation = parsed.data as M8WalletPresentation
  const credential = presentation.credential

  // ─── Request binding and freshness ─────────────────────────────────────
  if (request.status !== 'active') errors.push('identity request is not active')
  if (!(Date.parse(request.expiresAt) > now)) errors.push('identity request expired')
  if (presentation.requestId !== request.id) errors.push('presentation requestId does not match')
  if (presentation.nonce !== request.nonce) errors.push('presentation nonce does not match')
  if (presentation.audienceAppId !== request.audienceAppId) {
    errors.push('presentation audience does not match')
  }
  const presentedAt = Date.parse(presentation.issuedAt)
  const presentationExpiresAt = Date.parse(presentation.expiresAt)
  if (!(presentationExpiresAt > now)) errors.push('presentation expired')
  if (presentedAt > now + CLOCK_SKEW_MS) errors.push('presentation issuedAt is in the future')
  if (presentationExpiresAt - presentedAt > PRESENTATION_TTL_SECONDS * 1000 + CLOCK_SKEW_MS) {
    errors.push('presentation lifetime exceeds the allowed maximum')
  }

  // ─── Issuer ────────────────────────────────────────────────────────────
  const trustedIssuers = options.trustedIssuers ?? getTrustedIssuers()
  const issuer = trustedIssuers.find((entry) =>
    entry.did === credential.issuerDid && entry.keyId === credential.issuerKeyId
  ) ?? null
  if (!issuer) {
    errors.push('credential issuer is not trusted')
  } else if (issuer.status !== 'active' && issuer.status !== 'previous') {
    errors.push(`credential issuer is ${issuer.status}`)
  } else {
    const { signature, ...credentialPayload } = credential
    if (!verifyPayload(signedCredentialPayload(credentialPayload), signature, issuer.publicKeyPem)) {
      errors.push('credential issuer signature is invalid')
    }
  }
  if (!(Date.parse(credential.expiresAt) > now)) errors.push('credential expired')
  if (Date.parse(credential.issuedAt) > now + CLOCK_SKEW_MS) errors.push('credential issuedAt is in the future')

  // ─── Holder binding and subject ────────────────────────────────────────
  const holderKey = parseHolderPublicKey(credential.holderPublicKey)
  if (!credential.holderPublicKey) {
    errors.push('credential has no issuer-signed holder key')
  } else if (!holderKey) {
    errors.push('credential holder key is not an Ed25519 public key')
  } else {
    const { signature, ...presentationPayload } = presentation
    if (!verifyPayload(signedPresentationPayload(presentationPayload), signature, holderKey)) {
      errors.push('wallet presentation signature is invalid')
    }
  }
  if (credential.subjectDid !== options.expectedSubjectDid) {
    errors.push('credential subject does not match the requesting session')
  }

  // ─── Revocation ────────────────────────────────────────────────────────
  const revocation = options.revocationStatus(credential.revocationHash)
  if (revocation === 'unknown') {
    if (options.rejectUnknownRevocationStatus ?? true) {
      errors.push('credential revocation status is unknown')
    } else {
      warnings.push('credential revocation status is unknown')
    }
  } else if (revocation !== 'active') {
    errors.push(`credential is ${revocation}`)
  }

  // ─── Claims ────────────────────────────────────────────────────────────
  const requested = new Set(request.requestedElements.map((element) => element.id))
  const credentialClaims = credential.claims as Record<string, unknown>
  const disclosed = Object.keys(presentation.disclosedClaims) as M8IdentityElementId[]
  for (const claimId of disclosed) {
    if (!requested.has(claimId)) errors.push(`claim ${claimId} was not requested`)
    if (!Object.hasOwn(credentialClaims, claimId)) {
      errors.push(`claim ${claimId} is not in the credential`)
    } else if (presentation.disclosedClaims[claimId] !== credentialClaims[claimId]) {
      errors.push(`claim ${claimId} does not match the credential`)
    }
  }

  for (const element of request.requestedElements) {
    if (element.required && !Object.hasOwn(presentation.disclosedClaims, element.id)) {
      errors.push(`required claim ${element.id} was not disclosed`)
    }
    if (element.intentToStore.mode === 'may-store-until-revoked') {
      warnings.push(`long-lived storage requested for ${element.id}; audit retention policy`)
    }
  }

  // Full-credential disclosure: everything in the credential was revealed.
  const revealedClaimIds = Object.keys(credentialClaims) as M8IdentityElementId[]
  for (const claimId of revealedClaimIds) {
    if (issuer && !issuer.allowedElements.includes(claimId)) {
      errors.push(`issuer is not allowed to attest ${claimId}`)
    }
    if (requested.has(claimId)) continue
    if (LINKABLE_IDENTITY_ELEMENTS.includes(claimId)) {
      errors.push(`credential reveals unrequested linkable claim ${claimId}; full-credential disclosure cannot withhold it`)
    } else {
      warnings.push(`credential revealed unrequested claim ${claimId}`)
    }
  }

  const valid = errors.length === 0
  return {
    valid,
    requestId: request.id,
    presentationId: `${presentation.requestId}:${presentation.nonce}`,
    issuerDid: issuer?.did ?? credential.issuerDid,
    issuerName: issuer?.name ?? null,
    subjectDid: credential.subjectDid,
    disclosedClaims: valid
      ? Object.fromEntries(disclosed.map((id) => [id, credentialClaims[id]])) as M8IdentityCredentialClaims
      : {},
    disclosure: 'full-credential',
    revealedClaimIds,
    checkedAt,
    errors,
    warnings,
  }
}

/** Canonicalization, exported for the wallet conformance vectors only. */
export const __internal = {
  stableJson,
  signedCredentialPayload,
  signedPresentationPayload,
}
