import type { HttpContext } from '@adonisjs/core/http'
import type { NextFn } from '@adonisjs/core/types/http'
import env from '#start/env'
import { recordAbuse } from '../../src/services/abuseMonitor.js'

/**
 * In-memory rate limiter. Effective for single-process deployments.
 *
 * ⚠️ Known limitation: this Map is process-local. It will NOT share
 * state across PM2 clusters, multiple containers, or horizontal replicas.
 * An attacker distributing requests across workers/instances can bypass
 * the limit. For multi-instance deployments, replace with a Redis-backed
 * limiter (e.g., `@adonisjs/limiter` with Redis driver) or place rate
 * limiting at the edge (load balancer / API gateway).
 */

type RateLimitEntry = {
  count: number
  resetTime: number
}

const store = new Map<string, RateLimitEntry>()

function cleanupExpiredEntries() {
  const now = Date.now()
  for (const [key, entry] of store) {
    if (entry.resetTime <= now) {
      store.delete(key)
    }
  }
}

// Run cleanup every 60 seconds
setInterval(cleanupExpiredEntries, 60_000).unref()

function getClientIp(ctx: HttpContext): string {
  return (
    ctx.request.header('x-forwarded-for')?.split(',')[0]?.trim() ??
    ctx.request.header('x-real-ip') ??
    ctx.request.ip()
  )
}

type RateLimitCategory = 'auth' | 'community_read' | 'community_mutation' | 'community_vote' | 'general'

function getPath(ctx: HttpContext): string {
  return ctx.request.url().split('?')[0]
}

function getRateLimitCategory(ctx: HttpContext): RateLimitCategory {
  const path = getPath(ctx)
  const method = ctx.request.method().toUpperCase()

  if (path.startsWith('/v1/communities')) {
    if (method === 'POST' && /\/communities\/[^/]+\/actions\/[^/]+\/vote$/.test(path)) {
      return 'community_vote'
    }
    if (method === 'GET') {
      return 'community_read'
    }
    return 'community_mutation'
  }

  if (
    path.includes('/sessions/') ||
    path.includes('/identity/ine/') ||
    path.includes('/identity/revoke')
  ) {
    return 'auth'
  }

  return 'general'
}

function getRateLimitKey(ctx: HttpContext): string {
  const ip = getClientIp(ctx)
  const method = ctx.request.method()
  const category = getRateLimitCategory(ctx)
  const path = category === 'general' ? ctx.request.url() : category
  return `${ip}:${method}:${path}`
}

function getLimitForCategory(category: RateLimitCategory, limits: {
  maxRequests: number
  authMaxRequests: number
  communityReadMaxRequests: number
  communityMutationMaxRequests: number
  communityVoteMaxRequests: number
}) {
  switch (category) {
    case 'auth':
      return limits.authMaxRequests
    case 'community_read':
      return limits.communityReadMaxRequests
    case 'community_mutation':
      return limits.communityMutationMaxRequests
    case 'community_vote':
      return limits.communityVoteMaxRequests
    case 'general':
      return limits.maxRequests
  }
}

export default class RateLimitMiddleware {
  async handle(ctx: HttpContext, next: NextFn) {
    if (!env.get('RATE_LIMIT_ENABLED')) {
      return next()
    }

    const windowMs = env.get('RATE_LIMIT_WINDOW_MS')
    const maxRequests = env.get('RATE_LIMIT_MAX')
    const authMaxRequests = env.get('RATE_LIMIT_AUTH_MAX')
    const communityReadMaxRequests = env.get('RATE_LIMIT_COMMUNITY_READ_MAX')
    const communityMutationMaxRequests = env.get('RATE_LIMIT_COMMUNITY_MUTATION_MAX')
    const communityVoteMaxRequests = env.get('RATE_LIMIT_COMMUNITY_VOTE_MAX')
    const category = getRateLimitCategory(ctx)
    const key = getRateLimitKey(ctx)
    const now = Date.now()

    let entry = store.get(key)
    if (!entry || entry.resetTime <= now) {
      entry = { count: 0, resetTime: now + windowMs }
      store.set(key, entry)
    }

    const limit = getLimitForCategory(category, {
      maxRequests,
      authMaxRequests,
      communityReadMaxRequests,
      communityMutationMaxRequests,
      communityVoteMaxRequests,
    })

    if (entry.count >= limit) {
      recordAbuse({
        type: 'rate_limit_exceeded',
        ip: getClientIp(ctx),
        path: ctx.request.url(true),
        method: ctx.request.method(),
        userAgent: ctx.request.header('user-agent') ?? 'unknown',
        requestId: ctx.request.id() ?? 'unknown',
        sessionId: null,
        detail: `category=${category} limit=${limit} window=${windowMs}ms`,
      })

      return ctx.response.status(429).send({
        error: 'Too many requests',
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: Math.ceil((entry.resetTime - now) / 1000),
      })
    }

    entry.count++
    ctx.response.header('X-RateLimit-Limit', String(limit))
    ctx.response.header('X-RateLimit-Remaining', String(Math.max(0, limit - entry.count)))
    ctx.response.header('X-RateLimit-Reset', new Date(entry.resetTime).toISOString())

    return next()
  }
}
