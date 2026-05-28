import type { HttpContext } from '@adonisjs/core/http'
import type { NextFn } from '@adonisjs/core/types/http'
import { recordAbuse } from '../../src/services/abuseMonitor.js'

const MONITORED_STATUS_CODES = new Set([401, 403, 422, 429])

function getClientIp(ctx: HttpContext): string {
  return (
    ctx.request.header('x-forwarded-for')?.split(',')[0]?.trim() ??
    ctx.request.header('x-real-ip') ??
    ctx.request.ip()
  )
}

export default class AbuseMonitorMiddleware {
  async handle(ctx: HttpContext, next: NextFn) {
    await next()

    const status = ctx.response.response.statusCode
    if (!MONITORED_STATUS_CODES.has(status)) {
      return
    }

    const eventType =
      status === 401
        ? 'auth_failure'
        : status === 403
          ? 'suspicious_request'
          : status === 422
            ? 'validation_failure'
            : 'rate_limit_exceeded'

    recordAbuse({
      type: eventType,
      ip: getClientIp(ctx),
      path: ctx.request.url(true),
      method: ctx.request.method(),
      userAgent: ctx.request.header('user-agent') ?? 'unknown',
      requestId: ctx.request.id() ?? 'unknown',
      sessionId: null, // We don't extract JWT here to avoid auth logic duplication
      detail: `status=${status}`,
    })
  }
}
