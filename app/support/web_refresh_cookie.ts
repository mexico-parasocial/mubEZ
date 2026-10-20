import app from '@adonisjs/core/services/app'
import type { HttpContext } from '@adonisjs/core/http'
import env from '#start/env'

/**
 * Web sessions survive reloads without exposing the refresh token to page
 * scripts: the broker keeps it in an HttpOnly cookie and the page holds only
 * the short-lived access token in memory.
 *
 * A client opts in with this header. Because it is a non-safelisted header,
 * the browser preflights every cookie-mode request, and the broker also checks
 * the Origin against an explicit CORS allowlist, so a wildcard CORS deployment
 * cannot use cookie transport at all. The cookie is SameSite=Strict, which
 * requires the broker to be same-site with the PARA web origin.
 */
export const REFRESH_TRANSPORT_HEADER = 'x-m8-refresh-transport'

// `__Host-` pins the cookie to this host over HTTPS. Development brokers on
// plain http://localhost cannot set Secure cookies in every browser.
const cookieName = () => (app.inProduction ? '__Host-m8_refresh' : 'm8_refresh')

const cookieOptions = () => ({
  httpOnly: true,
  secure: app.inProduction,
  sameSite: 'strict' as const,
  path: '/',
  domain: '',
  maxAge: env.get('JWT_REFRESH_TTL_DAYS') * 86400,
})

function explicitOrigins(): string[] {
  return env
    .get('CORS_ORIGIN')
    .split(',')
    .map((value: string) => value.trim())
    .filter((value: string) => value && value !== '*')
}

export type RefreshTransport = 'body' | 'cookie' | 'refused'

/** Which transport this request asked for; `refused` when cookie mode is not allowed for its origin. */
export function refreshTransport(ctx: HttpContext): RefreshTransport {
  if (ctx.request.header(REFRESH_TRANSPORT_HEADER) !== 'cookie') return 'body'
  if (env.get('CORS_ORIGIN').split(',').some((value: string) => value.trim() === '*')) return 'refused'
  const origin = ctx.request.header('origin')
  return origin && explicitOrigins().includes(origin) ? 'cookie' : 'refused'
}

export function readRefreshCookie(ctx: HttpContext): string | null {
  const value: unknown = ctx.request.encryptedCookie(cookieName())
  return typeof value === 'string' && value ? value : null
}

/** Moves the refresh token into the cookie and returns the bundle without it. */
export function sendRefreshCookie<T extends { refreshToken: string }>(
  ctx: HttpContext,
  tokens: T,
): Omit<T, 'refreshToken'> & { refreshToken: null; refreshTransport: 'cookie' } {
  ctx.response.encryptedCookie(cookieName(), tokens.refreshToken, cookieOptions())
  ctx.response.header('cache-control', 'no-store')
  return { ...tokens, refreshToken: null, refreshTransport: 'cookie' }
}

export function clearRefreshCookie(ctx: HttpContext) {
  ctx.response.clearCookie(cookieName(), cookieOptions())
  ctx.response.header('cache-control', 'no-store')
}
