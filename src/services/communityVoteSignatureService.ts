import { createHash, createPublicKey, verify, type JsonWebKey, type KeyObject } from 'node:crypto'
import { resolveDidWithCache } from './didResolver.js'
import type { CommunityAction, CommunityActionVote } from '../types/index.js'
import { appError } from '../utils/errors.js'

const VOTE_PAYLOAD_TYPE = 'app.m8.community.vote'
const VOTE_PAYLOAD_VERSION = 1
const ED25519_MULTICODEC_PREFIX = [0xed, 0x01]
const BASE58BTC_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

export type CommunityVotePayload = {
  type: typeof VOTE_PAYLOAD_TYPE
  version: typeof VOTE_PAYLOAD_VERSION
  communityId: string
  actionId: string
  actionType: string
  payloadHash: string
  adminDid: string
  vote: CommunityActionVote
  signedAt: string
  nonce: string
}

export type CommunityVoteVerificationInput = {
  action: CommunityAction
  adminDid: string
  vote: CommunityActionVote
  signature: string
  signedAt: string
  nonce: string
  keyId?: string
}

export type CommunityVoteVerificationResult = {
  payload: CommunityVotePayload
  canonicalPayload: string
  signedPayloadHash: string
  verificationMethodId: string
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`
  }

  const record = value as Record<string, unknown>
  const keys = Object.keys(record).sort()
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(',')}}`
}

export function communityActionPayloadHash(payload: Record<string, unknown>): string {
  return `sha256:${createHash('sha256').update(canonicalJson(payload)).digest('base64url')}`
}

export function buildCommunityVotePayload(input: {
  action: Pick<CommunityAction, 'id' | 'communityId' | 'actionType' | 'payload'>
  adminDid: string
  vote: CommunityActionVote
  signedAt: string
  nonce: string
}): CommunityVotePayload {
  return {
    type: VOTE_PAYLOAD_TYPE,
    version: VOTE_PAYLOAD_VERSION,
    communityId: input.action.communityId,
    actionId: input.action.id,
    actionType: input.action.actionType,
    payloadHash: communityActionPayloadHash(input.action.payload),
    adminDid: input.adminDid,
    vote: input.vote,
    signedAt: input.signedAt,
    nonce: input.nonce,
  }
}

export function canonicalCommunityVotePayload(payload: CommunityVotePayload): string {
  return JSON.stringify({
    type: payload.type,
    version: payload.version,
    communityId: payload.communityId,
    actionId: payload.actionId,
    actionType: payload.actionType,
    payloadHash: payload.payloadHash,
    adminDid: payload.adminDid,
    vote: payload.vote,
    signedAt: payload.signedAt,
    nonce: payload.nonce,
  })
}

function validateNonce(nonce: string) {
  try {
    const bytes = Buffer.from(nonce, 'base64url')
    if (bytes.length !== 16) {
      throw new Error('invalid nonce length')
    }
  } catch {
    throw appError('Vote signature nonce must be 128-bit base64url', 422, 'INVALID_SIGNATURE_NONCE')
  }
}

function decodeBase58btc(value: string): Buffer {
  if (!value.startsWith('z')) {
    throw new Error('Only base58btc multibase keys are supported')
  }

  let decoded = 0n
  for (const char of value.slice(1)) {
    const index = BASE58BTC_ALPHABET.indexOf(char)
    if (index === -1) {
      throw new Error('Invalid base58btc character')
    }
    decoded = decoded * 58n + BigInt(index)
  }

  const bytes: number[] = []
  while (decoded > 0n) {
    bytes.unshift(Number(decoded % 256n))
    decoded /= 256n
  }

  for (const char of value.slice(1)) {
    if (char !== '1') break
    bytes.unshift(0)
  }

  return Buffer.from(bytes)
}

function keyFromVerificationMethod(method: Record<string, unknown>): KeyObject | null {
  const publicKeyJwk = method.publicKeyJwk as JsonWebKey | undefined
  if (publicKeyJwk?.kty === 'OKP' && publicKeyJwk.crv === 'Ed25519') {
    return createPublicKey({ key: publicKeyJwk, format: 'jwk' })
  }

  const publicKeyMultibase = method.publicKeyMultibase as string | undefined
  if (publicKeyMultibase) {
    const decoded = decodeBase58btc(publicKeyMultibase)
    if (
      decoded[0] !== ED25519_MULTICODEC_PREFIX[0] ||
      decoded[1] !== ED25519_MULTICODEC_PREFIX[1] ||
      decoded.length !== 34
    ) {
      return null
    }
    const x = decoded.subarray(2).toString('base64url')
    return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x }, format: 'jwk' })
  }

  const publicKeyPem = method.publicKeyPem as string | undefined
  if (publicKeyPem) {
    return createPublicKey(publicKeyPem)
  }

  return null
}

function normalizeMethodId(did: string, id: string) {
  return id.startsWith('#') ? `${did}${id}` : id
}

function methodIdMatches(did: string, actual: string, expected: string) {
  const actualFull = normalizeMethodId(did, actual)
  const expectedFull = normalizeMethodId(did, expected)
  return actual === expected || actualFull === expectedFull
}

function resolveAllowedMethods(did: string, didDocument: Record<string, unknown>) {
  const methods = ((didDocument.verificationMethod as Record<string, unknown>[] | undefined) ?? [])
  const allowedRefs = [
    ...(((didDocument.assertionMethod as unknown[] | undefined) ?? [])),
    ...(((didDocument.authentication as unknown[] | undefined) ?? [])),
  ]

  const allowedMethods: Record<string, unknown>[] = []
  for (const ref of allowedRefs) {
    if (typeof ref === 'string') {
      const method = methods.find((candidate) => {
        const id = candidate.id as string | undefined
        return id ? methodIdMatches(did, id, ref) : false
      })
      if (method) allowedMethods.push(method)
      continue
    }
    if (ref && typeof ref === 'object') {
      allowedMethods.push(ref as Record<string, unknown>)
    }
  }

  return allowedMethods
}

export async function verifyCommunityVoteSignature(
  input: CommunityVoteVerificationInput
): Promise<CommunityVoteVerificationResult> {
  validateNonce(input.nonce)

  const didDocument = await resolveDidWithCache(input.adminDid)
  if (!didDocument) {
    throw appError('Could not resolve admin DID for vote verification', 503, 'DID_RESOLUTION_FAILED')
  }

  const allowedMethods = resolveAllowedMethods(input.adminDid, didDocument as Record<string, unknown>)
  const matchingMethods = input.keyId
    ? allowedMethods.filter((method) => {
        const id = method.id as string | undefined
        return id ? methodIdMatches(input.adminDid, id, input.keyId as string) : false
      })
    : allowedMethods

  if (matchingMethods.length === 0) {
    throw appError('No usable DID key found for community vote', 403, 'DID_KEY_NOT_FOUND')
  }

  const payload = buildCommunityVotePayload(input)
  const canonicalPayload = canonicalCommunityVotePayload(payload)
  const signatureBytes = Buffer.from(input.signature, 'base64url')

  for (const method of matchingMethods) {
    const methodId = method.id as string | undefined
    if (!methodId) continue

    let publicKey: KeyObject | null = null
    try {
      publicKey = keyFromVerificationMethod(method)
    } catch {
      publicKey = null
    }
    if (!publicKey) continue

    const valid = verify(null, Buffer.from(canonicalPayload), publicKey, signatureBytes)
    if (valid) {
      return {
        payload,
        canonicalPayload,
        signedPayloadHash: `sha256:${createHash('sha256').update(canonicalPayload).digest('base64url')}`,
        verificationMethodId: normalizeMethodId(input.adminDid, methodId),
      }
    }
  }

  throw appError('Vote signature is invalid', 403, 'INVALID_VOTE_SIGNATURE')
}
