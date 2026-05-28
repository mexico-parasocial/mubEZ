import type { HttpContext } from '@adonisjs/core/http'
import type { NextFn } from '@adonisjs/core/types/http'
import { requireSessionId } from '#support/http'

/**
 * Authenticates the request by validating the Bearer JWT and
 * checking the session is active. Sets `ctx.sessionId` for
 * downstream handlers.
 */
export default class AuthMiddleware {
  async handle(ctx: HttpContext, next: NextFn) {
    const sessionId = await requireSessionId(ctx)
    if (!sessionId) {
      // requireSessionId already sent 401; do not continue
      return
    }

    ctx.sessionId = sessionId
    return next()
  }
}
