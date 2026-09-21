import type { HttpContext } from '@adonisjs/core/http'
import { buildClientMetadata } from '../../src/services/atprotoAuth.js'

/**
 * Serves the atproto OAuth client metadata document. Upstream PDSs fetch
 * `client_id` from this exact URL before authorizing the broker, so the
 * deployment must expose it over public https in production.
 */
export default class OauthClientMetadataController {
  async show(ctx: HttpContext) {
    return ctx.response
      .header('Cache-Control', 'public, max-age=3600')
      .send(buildClientMetadata())
  }
}
