import type { HttpContext } from '@adonisjs/core/http'
import type { NextFn } from '@adonisjs/core/types/http'
import env from '#start/env'

export default class SecurityHeadersMiddleware {
  async handle(ctx: HttpContext, next: NextFn) {
    if (!env.get('SECURITY_HEADERS_ENABLED')) {
      return next()
    }

    const response = ctx.response

    response.header('X-Content-Type-Options', 'nosniff')
    response.header('X-Frame-Options', 'DENY')
    response.header('X-XSS-Protection', '0')
    response.header('Referrer-Policy', 'strict-origin-when-cross-origin')

    if (env.get('NODE_ENV') === 'production') {
      response.header(
        'Strict-Transport-Security',
        'max-age=63072000; includeSubDomains'
      )
    }

    // Restrictive CSP that allows inline styles/scripts only when necessary.
    // The ZKP prover HTML is served as a static download, not rendered inline.
    response.header(
      'Content-Security-Policy',
      [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
      ].join('; ')
    )

    response.header(
      'Permissions-Policy',
      'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()'
    )

    return next()
  }
}
