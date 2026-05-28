import { generateKeyPairSync } from 'node:crypto'
import type { JsonWebKey } from 'node:crypto'
import { getDb } from '../../db/connection.js'
import { appError } from '../../utils/errors.js'
import { generateCommunityAtprotoKeypair, type CommunityAtprotoKeypair } from '../atproto/keyMaterial.js'

export interface CommunityKeyPair {
  publicKey: string // base64
  privateKey: string // base64
}

export interface CommunityDidDocument {
  '@context': string[]
  id: string
  alsoKnownAs?: string[]
  verificationMethod: Array<{
    id: string
    type: string
    controller: string
    publicKeyJwk?: {
      kty: string
      crv: string
      x: string
    }
    publicKeyMultibase?: string
  }>
  assertionMethod?: string[]
  authentication?: string[]
  service: Array<{
    id: string
    type: string
    serviceEndpoint: string
  }>
}

/**
 * Generate an Ed25519 keypair for a community.
 */
export function generateCommunityKeys(): CommunityKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
  return { publicKey, privateKey }
}

/**
 * Create a did:web DID document for a community.
 */
export function createDidDocument(community: {
  did: string
  handle: string | null
  pdsHost: string
  signingKeyPublic: string | null
  atprotoKeyPublicMultibase?: string | null
  atprotoKeyId?: string | null
}): CommunityDidDocument {
  if (!community.signingKeyPublic && !community.atprotoKeyPublicMultibase) {
    throw appError('Community has no signing key', 500, 'COMMUNITY_NO_SIGNING_KEY')
  }

  const did = community.did
  const handle = community.handle
  const atprotoKeyId = community.atprotoKeyId ?? `${did}#atproto`
  const verificationMethod: CommunityDidDocument['verificationMethod'] = []

  if (community.atprotoKeyPublicMultibase) {
    verificationMethod.push({
      id: atprotoKeyId,
      type: 'Multikey',
      controller: did,
      publicKeyMultibase: community.atprotoKeyPublicMultibase,
    })
  }

  if (community.signingKeyPublic) {
    const pem = community.signingKeyPublic
    const base64 = pem
      .replace(/-----BEGIN PUBLIC KEY-----/, '')
      .replace(/-----END PUBLIC KEY-----/, '')
      .replace(/\s/g, '')
    const rawKey = Buffer.from(base64, 'base64')

    // Ed25519 SPKI: 30 2a 30 05 06 03 2b 65 70 03 21 00 <32 bytes key>
    const keyBytes = rawKey.slice(-32)
    verificationMethod.push({
      id: `${did}#governance`,
      type: 'JsonWebKey2020',
      controller: did,
      publicKeyJwk: {
        kty: 'OKP',
        crv: 'Ed25519',
        x: keyBytes.toString('base64url'),
      },
    })
  }

  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: did,
    alsoKnownAs: handle ? [`at://${handle}`] : undefined,
    verificationMethod,
    assertionMethod: verificationMethod.map((method) => method.id),
    authentication: verificationMethod.map((method) => method.id),
    service: [
      {
        id: '#atproto_pds',
        type: 'AtprotoPersonalDataServer',
        serviceEndpoint: community.pdsHost || 'https://bsky.social',
      },
    ],
  }
}

/**
 * Generate and store a signing keypair for a community.
 */
export function provisionCommunityKeys(communityId: string): CommunityKeyPair {
  const db = getDb()
  const keys = generateCommunityKeys()
  const community = db.prepare('SELECT did FROM communities WHERE id = ?').get(communityId) as
    | { did: string }
    | undefined
  if (!community) {
    throw appError('Community not found', 404, 'COMMUNITY_NOT_FOUND')
  }
  const atprotoKeys = generateCommunityAtprotoKeypair(community.did)

  db.prepare(
    `UPDATE communities
     SET signing_key_public = ?,
         signing_key_private = ?,
         community_atproto_key_public_multibase = ?,
         community_atproto_key_private_jwk = ?,
         community_atproto_key_type = ?,
         community_atproto_key_id = ?
     WHERE id = ?`
  ).run(
    keys.publicKey,
    keys.privateKey,
    atprotoKeys.publicMultibase,
    JSON.stringify(atprotoKeys.privateJwk),
    atprotoKeys.keyType,
    atprotoKeys.keyId,
    communityId
  )

  return keys
}

export function ensureCommunityAtprotoKeys(communityId: string): CommunityAtprotoKeypair {
  const db = getDb()

  // Fast path: keys already provisioned
  const row = db.prepare(`
    SELECT did, community_atproto_key_public_multibase, community_atproto_key_private_jwk,
           community_atproto_key_type, community_atproto_key_id
    FROM communities
    WHERE id = ?
  `).get(communityId) as Record<string, unknown> | undefined

  if (!row) {
    throw appError('Community not found', 404, 'COMMUNITY_NOT_FOUND')
  }

  if (row.community_atproto_key_id) {
    return {
      publicMultibase: row.community_atproto_key_public_multibase as string,
      privateJwk: JSON.parse(row.community_atproto_key_private_jwk as string) as JsonWebKey,
      keyType: 'secp256k1',
      keyId: row.community_atproto_key_id as string,
    }
  }

  // Race-condition-safe provisioning: only update if key_id is still NULL.
  // If another request already provisioned keys, result.changes === 0 and we
  // read the existing keys instead of overwriting them.
  const keys = generateCommunityAtprotoKeypair(row.did as string)
  const result = db.prepare(`
    UPDATE communities
    SET community_atproto_key_public_multibase = ?,
        community_atproto_key_private_jwk = ?,
        community_atproto_key_type = ?,
        community_atproto_key_id = ?
    WHERE id = ? AND community_atproto_key_id IS NULL
  `).run(keys.publicMultibase, JSON.stringify(keys.privateJwk), keys.keyType, keys.keyId, communityId)

  if (result.changes > 0) {
    return keys
  }

  // Lost the race — another request provisioned keys. Read theirs.
  const updatedRow = db.prepare(`
    SELECT community_atproto_key_public_multibase, community_atproto_key_private_jwk,
           community_atproto_key_type, community_atproto_key_id
    FROM communities
    WHERE id = ?
  `).get(communityId) as Record<string, unknown>

  return {
    publicMultibase: updatedRow.community_atproto_key_public_multibase as string,
    privateJwk: JSON.parse(updatedRow.community_atproto_key_private_jwk as string) as JsonWebKey,
    keyType: 'secp256k1',
    keyId: updatedRow.community_atproto_key_id as string,
  }
}
