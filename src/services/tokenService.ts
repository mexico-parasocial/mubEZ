import { randomUUID } from 'node:crypto'
import { SignJWT, jwtVerify, type JWTPayload } from 'jose'
import env from '#start/env'
import { getDb } from '../db/connection.js'
import { hashRefreshToken } from './sessionService.js'

const jwtSecret = new TextEncoder().encode(env.get('JWT_SECRET'))

export class TokenIssueError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly status = 401,
  ) {
    super(message)
  }
}

function nowIso() {
  return new Date().toISOString()
}

function getTokenSession(sessionId: string) {
  return getDb()
    .prepare('SELECT session_id, authenticated_at, status FROM sessions WHERE session_id = ?')
    .get(sessionId) as { session_id: string; authenticated_at: string | null; status: string } | undefined
}

export function assertCanIssueTokens(sessionId: string) {
  const session = getTokenSession(sessionId)
  if (!session) {
    throw new TokenIssueError('Session not found', 'SESSION_NOT_FOUND')
  }
  if (!session.authenticated_at) {
    throw new TokenIssueError('Session is not authenticated', 'SESSION_NOT_AUTHENTICATED')
  }
  if (session.status !== 'active') {
    throw new TokenIssueError('Session is not active', 'SESSION_NOT_ACTIVE')
  }
}

function writeLedger(sessionId: string, action: string, targetType: string, targetId: string, detail: unknown) {
  getDb().prepare(`
    INSERT INTO ledger (session_id, action, target_type, target_id, detail_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(sessionId, action, targetType, targetId, JSON.stringify(detail ?? {}), nowIso())
}

export function signAccessToken(sessionId: string) {
  const now = Math.floor(Date.now() / 1000)

  return new SignJWT({ type: 'access' })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setSubject(sessionId)
    .setIssuer(env.get('JWT_ISSUER'))
    .setAudience(env.get('JWT_AUDIENCE'))
    .setIssuedAt(now)
    .setExpirationTime(now + env.get('JWT_ACCESS_TTL_SECONDS'))
    .sign(jwtSecret)
}

export async function verifyAccessToken(token: string): Promise<JWTPayload | null> {
  try {
    const { payload } = await jwtVerify(token, jwtSecret, {
      algorithms: ['HS256'],
      audience: env.get('JWT_AUDIENCE'),
      issuer: env.get('JWT_ISSUER'),
    })
    if (payload.type !== 'access' || !payload.sub) return null
    return payload
  } catch {
    return null
  }
}

export async function issueTokenBundle(sessionId: string, detail: Record<string, unknown> = {}) {
  assertCanIssueTokens(sessionId)

  const accessToken = await signAccessToken(sessionId)
  const refreshToken = randomUUID()
  const tokenHash = hashRefreshToken(refreshToken)
  const expiresAt = new Date(Date.now() + env.get('JWT_REFRESH_TTL_DAYS') * 86400_000).toISOString()

  getDb()
    .prepare('INSERT INTO refresh_tokens (token_hash, session_id, expires_at) VALUES (?, ?, ?)')
    .run(tokenHash, sessionId, expiresAt)

  writeLedger(sessionId, 'TokenIssued', 'session', sessionId, {
    ...detail,
    refreshTokenHash: tokenHash,
    refreshExpiresAt: expiresAt,
    accessTtlSeconds: env.get('JWT_ACCESS_TTL_SECONDS'),
  })

  return { accessToken, refreshToken, expiresIn: env.get('JWT_ACCESS_TTL_SECONDS') }
}

export async function rotateRefreshToken(refreshToken: string) {
  const tokenHash = hashRefreshToken(refreshToken)
  const db = getDb()
  const row = db
    .prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?')
    .get(tokenHash) as Record<string, unknown> | undefined

  if (!row) {
    throw new TokenIssueError('Invalid refresh token', 'INVALID_REFRESH_TOKEN')
  }

  const sessionId = row.session_id as string
  if (row.revoked_at) {
    writeLedger(sessionId, 'RefreshTokenReuseRejected', 'refresh_token', tokenHash, {
      revokedAt: row.revoked_at,
      rotatedAt: row.rotated_at ?? null,
    })
    throw new TokenIssueError('Invalid refresh token', 'REFRESH_TOKEN_REUSED')
  }

  if (new Date(row.expires_at as string).getTime() <= Date.now()) {
    db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL')
      .run(nowIso(), tokenHash)
    throw new TokenIssueError('Invalid refresh token', 'REFRESH_TOKEN_EXPIRED')
  }

  assertCanIssueTokens(sessionId)

  const nextRefreshToken = randomUUID()
  const nextTokenHash = hashRefreshToken(nextRefreshToken)
  const nextExpiresAt = new Date(Date.now() + env.get('JWT_REFRESH_TTL_DAYS') * 86400_000).toISOString()
  const accessToken = await signAccessToken(sessionId)
  const rotatedAt = nowIso()

  db.transaction(() => {
    db.prepare('INSERT INTO refresh_tokens (token_hash, session_id, expires_at) VALUES (?, ?, ?)')
      .run(nextTokenHash, sessionId, nextExpiresAt)
    db.prepare(`
      UPDATE refresh_tokens
      SET revoked_at = ?,
          rotated_at = ?,
          replaced_by_token_hash = ?
      WHERE token_hash = ? AND revoked_at IS NULL
    `).run(rotatedAt, rotatedAt, nextTokenHash, tokenHash)
  })()

  writeLedger(sessionId, 'RefreshTokenRotated', 'refresh_token', tokenHash, {
    replacementHash: nextTokenHash,
    refreshExpiresAt: nextExpiresAt,
  })

  return {
    accessToken,
    refreshToken: nextRefreshToken,
    expiresIn: env.get('JWT_ACCESS_TTL_SECONDS'),
  }
}

export function revokeSessionRefreshTokens(sessionId: string, reason = 'logout') {
  getDb()
    .prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE session_id = ? AND revoked_at IS NULL')
    .run(nowIso(), sessionId)
  writeLedger(sessionId, 'SessionRefreshTokensRevoked', 'session', sessionId, { reason })
}
