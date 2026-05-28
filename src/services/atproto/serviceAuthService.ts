import { randomBytes } from 'node:crypto'
import type { JsonWebKey } from 'node:crypto'
import { getDb } from '../../db/connection.js'
import { appError } from '../../utils/errors.js'
import { signEs256kCompactJwt } from './keyMaterial.js'
import { ensureCommunityAtprotoKeys } from '../community/didService.js'

export type ServiceAuthToken = {
  token: string
  issuer: string
  audience: string
  lxm: string
  expiresAt: string
  keyId: string
}

type CommunityAuthRow = {
  did: string
  community_atproto_key_private_jwk: string | null
  community_atproto_key_id: string | null
}

export async function resolvePdsServiceDid(pdsHost: string): Promise<string> {
  const base = pdsHost.endsWith('/') ? pdsHost.slice(0, -1) : pdsHost
  const response = await fetch(`${base}/xrpc/com.atproto.server.describeServer`, {
    headers: { accept: 'application/json' },
  })

  if (!response.ok) {
    throw appError('Could not describe PDS server', 503, 'PDS_DESCRIBE_FAILED')
  }

  const body = await response.json() as Record<string, unknown>
  const did = body.did
  if (typeof did !== 'string' || !did.startsWith('did:')) {
    throw appError('PDS describeServer response did not include a DID', 503, 'PDS_DID_MISSING')
  }

  return did
}

export function createCommunityServiceAuthToken(
  communityId: string,
  audienceDid: string,
  lxm: string,
  opts?: { now?: Date; ttlSeconds?: number; jti?: string }
): ServiceAuthToken {
  const db = getDb()
  let row = db.prepare(`
    SELECT did, community_atproto_key_private_jwk, community_atproto_key_id
    FROM communities
    WHERE id = ?
  `).get(communityId) as CommunityAuthRow | undefined

  if (!row) {
    throw appError('Community not found', 404, 'COMMUNITY_NOT_FOUND')
  }

  if (!row.community_atproto_key_private_jwk || !row.community_atproto_key_id) {
    ensureCommunityAtprotoKeys(communityId)
    row = db.prepare(`
      SELECT did, community_atproto_key_private_jwk, community_atproto_key_id
      FROM communities
      WHERE id = ?
    `).get(communityId) as CommunityAuthRow | undefined
  }

  if (!row?.community_atproto_key_private_jwk || !row.community_atproto_key_id) {
    throw appError('Community ATProto service auth key is missing', 503, 'COMMUNITY_SERVICE_AUTH_KEY_MISSING')
  }

  const now = opts?.now ?? new Date()
  const issuedAt = Math.floor(now.getTime() / 1000)
  const ttlSeconds = opts?.ttlSeconds ?? 60
  const expiresAt = issuedAt + ttlSeconds
  const jti = opts?.jti ?? randomBytes(16).toString('hex')

  const header = {
    typ: 'JWT',
    alg: 'ES256K',
    kid: row.community_atproto_key_id,
  }
  const payload = {
    iss: row.did,
    aud: audienceDid,
    iat: issuedAt,
    exp: expiresAt,
    lxm,
    jti,
  }

  const signingInput = `${base64urlJson(header)}.${base64urlJson(payload)}`
  const signature = signEs256kCompactJwt(signingInput, JSON.parse(row.community_atproto_key_private_jwk) as JsonWebKey)

  return {
    token: `${signingInput}.${signature}`,
    issuer: row.did,
    audience: audienceDid,
    lxm,
    expiresAt: new Date(expiresAt * 1000).toISOString(),
    keyId: row.community_atproto_key_id,
  }
}

function base64urlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url')
}
