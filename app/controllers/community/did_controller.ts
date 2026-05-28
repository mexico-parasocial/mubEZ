import type { HttpContext } from '@adonisjs/core/http'
import { getDb } from '../../../src/db/connection.js'
import { createDidDocument, ensureCommunityAtprotoKeys } from '../../../src/services/community/didService.js'

export default class DidController {
  async webDid(ctx: HttpContext) {
    const host = ctx.request.header('host') || ''
    const communityHandle = ctx.request.qs().community as string | undefined

    const db = getDb()

    // Look up community by handle or DID
    let row: Record<string, unknown> | undefined

    if (communityHandle) {
      row = db.prepare('SELECT * FROM communities WHERE handle = ?').get(communityHandle) as
        | Record<string, unknown>
        | undefined
    }

    // Fallback: try to match by host in handle (e.g., communities.m8.dev:mi-partido)
    if (!row && host) {
      // Look for communities whose handle ends with this host
      row = db
        .prepare(`
          SELECT * FROM communities
          WHERE handle LIKE ?
            AND (signing_key_public IS NOT NULL OR community_atproto_key_public_multibase IS NOT NULL)
          LIMIT 1
        `)
        .get(`%${host}%`) as Record<string, unknown> | undefined
    }

    if (!row) {
      return ctx.response.status(404).send({ error: 'DID document not found' })
    }

    if (!row.signing_key_public && !row.community_atproto_key_public_multibase) {
      return ctx.response.status(404).send({ error: 'Community has no signing key' })
    }

    if (!row.community_atproto_key_public_multibase) {
      const atprotoKeys = ensureCommunityAtprotoKeys(row.id as string)
      row.community_atproto_key_public_multibase = atprotoKeys.publicMultibase
      row.community_atproto_key_id = atprotoKeys.keyId
    }

    const doc = createDidDocument({
      did: row.did as string,
      handle: (row.handle as string) ?? null,
      pdsHost: (row.pds_host as string) || '',
      signingKeyPublic: (row.signing_key_public as string) ?? null,
      atprotoKeyPublicMultibase: (row.community_atproto_key_public_multibase as string) ?? null,
      atprotoKeyId: (row.community_atproto_key_id as string) ?? null,
    })

    ctx.response.header('Content-Type', 'application/did+json')
    ctx.response.header('Cache-Control', 'public, max-age=3600')
    return ctx.response.send(doc)
  }
}
