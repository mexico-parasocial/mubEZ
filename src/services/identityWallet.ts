import {
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto'
import env from '#start/env'
import { Features, isFeatureEnabled } from './features.js'
import { getSharedIssuerKeyStore, resetSharedIssuerKeyStore } from './issuerKeyStore.js'
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

type SigningIssuer = {
  did: string
  keyId: string
  name: string
  privateKey: KeyObject
  publicKeyPem: string
}

function loadConfiguredIssuer() {
  try {
    const store = getSharedIssuerKeyStore()
    const key = store.getSigningKey()
    return {
      did: key.did,
      keyId: key.keyId,
      privateKey: key.privateKey,
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
      privateKey: configuredIssuer.privateKey,
      publicKeyPem: configuredIssuer.publicKeyPem,
    }
  }

  const demoIssuer = getDemoIneIssuerKey()
  return {
    did: DEMO_ISSUER_DID,
    keyId: DEMO_ISSUER_KEY_ID,
    name: 'Instituto Nacional Electoral',
    privateKey: demoIssuer.privateKey,
    publicKeyPem: demoIssuer.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
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
  return stableJson({
    id: credential.id,
    issuerDid: credential.issuerDid,
    issuerKeyId: credential.issuerKeyId,
    subjectDid: credential.subjectDid,
    issuedAt: credential.issuedAt,
    expiresAt: credential.expiresAt,
    claims: credential.claims,
    revocationHash: credential.revocationHash,
    signatureAlg: credential.signatureAlg,
  })
}

function signedPresentationPayload(presentation: Omit<M8WalletPresentation, 'signature'>) {
  return stableJson(presentation)
}

function signPayload(payload: string, privateKey: KeyObject) {
  return base64url(sign(null, Buffer.from(payload), privateKey))
}

function verifyPayload(payload: string, signature: string, publicKeyPem: string) {
  return verify(null, Buffer.from(payload), publicKeyPem, Buffer.from(signature, 'base64url'))
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

export function createIssuerSignedCredential(params: {
  subjectDid: string
  claims: M8IdentityCredentialClaims
  revocationHash: string
  expiresAt?: string
}): M8IdentityCredential {
  const issuer = getSigningIssuer()
  const unsignedCredential: Omit<M8IdentityCredential, 'signature'> = {
    id: `credential-${randomUUID()}`,
    issuerDid: issuer.did,
    issuerKeyId: issuer.keyId,
    subjectDid: params.subjectDid,
    issuedAt: nowIso(),
    expiresAt: params.expiresAt ?? addSeconds(365 * 24 * 60 * 60),
    claims: params.claims,
    revocationHash: params.revocationHash,
    signatureAlg: 'Ed25519',
  }

  return {
    ...unsignedCredential,
    signature: signPayload(signedCredentialPayload(unsignedCredential), issuer.privateKey),
  }
}

export function createDemoWalletPresentation(params: {
  request: M8IdentityRequest
  subjectDid: string
  selectedElementIds?: M8IdentityElementId[]
}): M8WalletPresentation {
  const selected = new Set(
    params.selectedElementIds ?? params.request.requestedElements.map((element) => element.id)
  )
  const claims: M8IdentityCredentialClaims = {
    age_over_18: true,
    age_over_21: true,
    citizenship: 'MX',
    district_hash: 'sha256:district:mx-jal-10',
    curp_hash: 'sha256:curp:redacted-demo',
  }
  const disclosedClaims = Object.fromEntries(
    Object.entries(claims).filter(([key]) => selected.has(key as M8IdentityElementId))
  ) as M8IdentityCredentialClaims

  const walletKey = getDemoWalletKey()
  const credential = createIssuerSignedCredential({
    subjectDid: params.subjectDid,
    claims,
    revocationHash: base64url(randomBytes(32)),
  })

  const unsignedPresentation: Omit<M8WalletPresentation, 'signature'> = {
    type: 'm8.identity.presentation.v1',
    requestId: params.request.id,
    nonce: params.request.nonce,
    audienceAppId: params.request.audienceAppId,
    credential,
    disclosedClaims,
    devicePublicKey: walletKey.publicKey.export({ type: 'spki', format: 'pem' }).toString().trim(),
    issuedAt: nowIso(),
    expiresAt: addSeconds(PRESENTATION_TTL_SECONDS),
    signatureAlg: 'Ed25519',
  }

  return {
    ...unsignedPresentation,
    signature: signPayload(signedPresentationPayload(unsignedPresentation), walletKey.privateKey),
  }
}

export function verifyWalletPresentation(
  request: M8IdentityRequest,
  presentation: M8WalletPresentation,
  trustedIssuers = getTrustedIssuers()
): M8IdentityVerificationResult {
  const errors: string[] = []
  const warnings: string[] = []
  const checkedAt = nowIso()
  const issuer = trustedIssuers.find((entry) =>
    entry.did === presentation.credential?.issuerDid &&
    entry.keyId === presentation.credential?.issuerKeyId
  ) ?? null

  if (request.status !== 'active') errors.push('identity request is not active')
  if (new Date(request.expiresAt).getTime() <= Date.now()) errors.push('identity request expired')
  if (presentation.type !== 'm8.identity.presentation.v1') errors.push('unsupported presentation type')
  if (presentation.requestId !== request.id) errors.push('presentation requestId does not match')
  if (presentation.nonce !== request.nonce) errors.push('presentation nonce does not match')
  if (presentation.audienceAppId !== request.audienceAppId) {
    errors.push('presentation audience does not match')
  }
  if (new Date(presentation.expiresAt).getTime() <= Date.now()) {
    errors.push('presentation expired')
  }
  if (new Date(presentation.credential.expiresAt).getTime() <= Date.now()) {
    errors.push('credential expired')
  }
  if (!issuer) {
    errors.push('credential issuer is not trusted')
  } else if (issuer.status !== 'active' && issuer.status !== 'previous') {
    errors.push(`credential issuer is ${issuer.status}`)
  }

  const requested = new Set(request.requestedElements.map((element) => element.id))
  const disclosed = Object.keys(presentation.disclosedClaims) as M8IdentityElementId[]
  for (const claimId of disclosed) {
    if (!requested.has(claimId)) errors.push(`claim ${claimId} was not requested`)
    if (issuer && !issuer.allowedElements.includes(claimId)) {
      errors.push(`issuer is not allowed to attest ${claimId}`)
    }
  }

  for (const element of request.requestedElements) {
    if (element.required && !(element.id in presentation.disclosedClaims)) {
      errors.push(`required claim ${element.id} was not disclosed`)
    }
    if (element.intentToStore.mode === 'may-store-until-revoked') {
      warnings.push(`long-lived storage requested for ${element.id}; audit retention policy`)
    }
  }

  if (issuer) {
    const { signature, ...credentialPayload } = presentation.credential
    if (!verifyPayload(signedCredentialPayload(credentialPayload), signature, issuer.publicKeyPem)) {
      errors.push('credential issuer signature is invalid')
    }
  }

  const { signature, ...presentationPayload } = presentation
  if (!verifyPayload(signedPresentationPayload(presentationPayload), signature, presentation.devicePublicKey)) {
    errors.push('wallet presentation signature is invalid')
  }

  return {
    valid: errors.length === 0,
    requestId: request.id,
    presentationId: `${presentation.requestId}:${presentation.nonce}`,
    issuerDid: issuer?.did ?? presentation.credential?.issuerDid ?? null,
    issuerName: issuer?.name ?? null,
    subjectDid: presentation.credential?.subjectDid ?? null,
    disclosedClaims: errors.length === 0 ? presentation.disclosedClaims : {},
    checkedAt,
    errors,
    warnings,
  }
}
