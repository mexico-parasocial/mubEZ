import app from '@adonisjs/core/services/app'
import { type HttpContext, ExceptionHandler } from '@adonisjs/core/http'

type HttpError = Error & {
  code?: string
  status?: number
  statusCode?: number
}

function sanitizeMessage(error: HttpError, statusCode: number | undefined): string {
  if (!statusCode || statusCode < 500) {
    return error.message || 'Request error'
  }
  // In production, never leak internal 5xx details to the client
  return app.inProduction ? 'Internal server error' : error.message
}

export default class HttpExceptionHandler extends ExceptionHandler {
  protected debug = !app.inProduction

  async handle(error: unknown, ctx: HttpContext) {
    const requestId = ctx.request.id() ?? 'unknown'
    const timestamp = new Date().toISOString()

    if (error instanceof Error) {
      const httpError = error as HttpError
      const statusCode = httpError.statusCode ?? httpError.status

      if (statusCode && statusCode >= 400 && statusCode < 500) {
        return ctx.response.status(statusCode).send({
          error: sanitizeMessage(httpError, statusCode),
          code: httpError.code || 'REQUEST_ERROR',
          requestId,
          timestamp,
        })
      }

      // Handle 5xx and unhandled errors with a sanitized response
      const fiveHundredStatus = statusCode && statusCode >= 500 ? statusCode : 500
      return ctx.response.status(fiveHundredStatus).send({
        error: sanitizeMessage(httpError, fiveHundredStatus),
        code: httpError.code || 'INTERNAL_ERROR',
        requestId,
        timestamp,
      })
    }

    // Unknown error type
    return ctx.response.status(500).send({
      error: app.inProduction ? 'Internal server error' : 'Unknown error',
      code: 'INTERNAL_ERROR',
      requestId,
      timestamp,
    })
  }

  async report(error: unknown, ctx: HttpContext) {
    const requestId = ctx.request.id() ?? 'unknown'

    if (error instanceof Error) {
      const httpError = error as HttpError
      const statusCode = httpError.statusCode ?? httpError.status

      if (statusCode && statusCode >= 400 && statusCode < 500) {
        // Log 4xx at warn level with context for abuse analysis
        ctx.logger.warn(
          { requestId, statusCode, code: httpError.code, err: error },
          'Client error'
        )
        return
      }

      // Log 5xx at error level with full context
      ctx.logger.error(
        { requestId, statusCode, code: httpError.code, err: error },
        'Server error'
      )
      return
    }

    ctx.logger.error({ requestId, err: error }, 'Unknown error')
  }
}
