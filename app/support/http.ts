import type { HttpContext } from '@adonisjs/core/http'
import type { z } from 'zod'
import { getDb } from '../../src/db/connection.js'
import { createT, resolveLocale } from '../../src/i18n/index.js'
export { signAccessToken, verifyAccessToken } from '../../src/services/tokenService.js'
import { verifyAccessToken } from '../../src/services/tokenService.js'

export async function requireSessionId(ctx: HttpContext) {
  const authorization = ctx.request.header('authorization') ?? ''
  const match = authorization.match(/^Bearer\s+(.+)$/i)
  const token = match?.[1]
  const payload = token ? await verifyAccessToken(token) : null

  if (!payload?.sub) {
    ctx.response.status(401).send({ error: 'Unauthorized' })
    return null
  }

  const row = getDb()
    .prepare('SELECT authenticated_at, status FROM sessions WHERE session_id = ?')
    .get(payload.sub) as { authenticated_at: string | null; status: string } | undefined

  if (!row?.authenticated_at || row.status !== 'active') {
    ctx.response.status(401).send({ error: 'Unauthorized' })
    return null
  }

  return payload.sub
}

export function validateBody<T extends z.ZodTypeAny>(ctx: HttpContext, schema: T): z.infer<T> | null {
  const result = schema.safeParse(ctx.request.body())
  if (result.success) return result.data

  ctx.response.status(422).send({
    error: 'Validation failed',
    issues: result.error.issues.map((issue) => ({
      path: issue.path.join('.'),
      message: issue.message,
    })),
  })
  return null
}

export function getSessionId(ctx: HttpContext): string {
  if (!ctx.sessionId) {
    throw new Error('Session ID not available. Ensure auth middleware is applied to this route.')
  }
  return ctx.sessionId
}

export async function getSessionDid(ctx: HttpContext): Promise<string> {
  const sessionId = getSessionId(ctx)
  const row = getDb()
    .prepare('SELECT did FROM sessions WHERE session_id = ?')
    .get(sessionId) as { did: string } | undefined
  if (!row) {
    const err = new Error('Session not found')
    Object.assign(err, { statusCode: 404, code: 'SESSION_NOT_FOUND' })
    throw err
  }
  return row.did
}

export function t(ctx: HttpContext) {
  const locale = resolveLocale(ctx.request.header('accept-language') ?? undefined)
  return createT(locale)
}
