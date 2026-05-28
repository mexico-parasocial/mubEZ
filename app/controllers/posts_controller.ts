import { z } from 'zod'
import type { HttpContext } from '@adonisjs/core/http'
import { getSessionId, validateBody } from '#support/http'
import { hydrateSession } from '../../src/services/sessionService.js'
import { createBlueskyPost, AtprotoAgentError } from '../../src/services/atprotoAgent.js'

const createPostSchema = z.object({
  text: z.string().min(1).max(3000),
  surface: z.enum(['public', 'civic', 'dating']).optional(),
  replyTo: z.object({
    uri: z.string(),
    cid: z.string(),
  }).optional(),
})

export default class PostsController {
  /**
   * Publish a post to the user's PDS (Bluesky/AT Protocol).
   *
   * The surface determines where the post is published:
   * - public (orbit): published to app.bsky.feed.post
   * - civic (signal): reserved for future civic-specific posting
   * - dating (spark): not published to public feeds
   */
  async store(ctx: HttpContext) {
    const body = validateBody(ctx, createPostSchema)
    if (!body) return

    const sessionId = getSessionId(ctx)
    const session = hydrateSession(sessionId)

    // Only public (orbit) posts go to Bluesky for now
    const surface = body.surface ?? session.activeSurfaceId
    if (surface !== 'public') {
      return ctx.response.status(400).send({
        error: `Cross-posting is only supported for public (orbit) surface. Use your PDS client for ${surface} posts.`,
        code: 'SURFACE_NOT_SUPPORTED',
      })
    }

    // Verify the session was created with sufficient OAuth scope
    if (!session.oauthScope.includes('rpc:com.atproto.repo.applyWrites')) {
      return ctx.response.status(403).send({
        error: 'Your session does not have write permission. Please re-authenticate with public surface to enable posting.',
        code: 'INSUFFICIENT_OAUTH_SCOPE',
        requiredScope: 'rpc:com.atproto.repo.applyWrites',
        currentScope: session.oauthScope,
      })
    }

    try {
      const result = await createBlueskyPost(session.did, {
        text: body.text,
        ...(body.replyTo
          ? {
              reply: {
                root: body.replyTo,
                parent: body.replyTo,
              },
            }
          : {}),
      })

      return ctx.response.send({
        post: {
          uri: result.uri,
          cid: result.cid,
          text: body.text,
          surface,
          publishedAt: new Date().toISOString(),
        },
      })
    } catch (err) {
      if (err instanceof AtprotoAgentError) {
        return ctx.response.status(err.status).send({
          error: err.message,
          code: err.code,
        })
      }

      const message = err instanceof Error ? err.message : 'Failed to publish post'
      return ctx.response.status(500).send({
        error: message,
        code: 'PUBLISH_FAILED',
      })
    }
  }
}
