import { randomUUID } from 'node:crypto'
import { getDb } from '../db/connection.js'

const OAUTH_ATTEMPT_TTL_MS = 10 * 60 * 1000

export type OAuthLoginAttempt = {
  id: string
  state: string
  identifier: string
  oauthUrl: string
  scope: string
  status: 'pending' | 'completed' | 'expired' | 'failed'
  createdAt: string
  expiresAt: string
  completedAt: string | null
  failedAt: string | null
  resolvedDid: string | null
  sessionId: string | null
  errorCode: string | null
}

function nowIso() {
  return new Date().toISOString()
}

function mapAttempt(row: Record<string, unknown>): OAuthLoginAttempt {
  return {
    id: row.id as string,
    state: row.state as string,
    identifier: row.identifier as string,
    oauthUrl: row.oauth_url as string,
    scope: (row.scope as string) || 'atproto',
    status: row.status as OAuthLoginAttempt['status'],
    createdAt: row.created_at as string,
    expiresAt: row.expires_at as string,
    completedAt: row.completed_at as string | null,
    failedAt: row.failed_at as string | null,
    resolvedDid: row.resolved_did as string | null,
    sessionId: row.session_id as string | null,
    errorCode: row.error_code as string | null,
  }
}

export function createOAuthLoginAttempt(input: {
  identifier: string
  state: string
  oauthUrl: string
  scope?: string
}): OAuthLoginAttempt {
  const id = `oauth-attempt-${randomUUID()}`
  const createdAt = nowIso()
  const expiresAt = new Date(Date.now() + OAUTH_ATTEMPT_TTL_MS).toISOString()

  getDb().prepare(`
    INSERT INTO oauth_login_attempts
      (id, state, identifier, oauth_url, scope, status, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
  `).run(id, input.state, input.identifier, input.oauthUrl, input.scope || 'atproto', createdAt, expiresAt)

  return {
    id,
    state: input.state,
    identifier: input.identifier,
    oauthUrl: input.oauthUrl,
    scope: input.scope || 'atproto',
    status: 'pending',
    createdAt,
    expiresAt,
    completedAt: null,
    failedAt: null,
    resolvedDid: null,
    sessionId: null,
    errorCode: null,
  }
}

export function getOAuthLoginAttemptByState(state: string): OAuthLoginAttempt | null {
  const row = getDb()
    .prepare('SELECT * FROM oauth_login_attempts WHERE state = ?')
    .get(state) as Record<string, unknown> | undefined

  return row ? mapAttempt(row) : null
}

export function getPendingOAuthLoginAttempt(state: string): OAuthLoginAttempt | null {
  const attempt = getOAuthLoginAttemptByState(state)
  if (!attempt) return null

  if (attempt.status !== 'pending') return null
  if (new Date(attempt.expiresAt).getTime() <= Date.now()) {
    expireOAuthLoginAttempt(attempt.id)
    return null
  }

  return attempt
}

export function completeOAuthLoginAttempt(input: {
  id: string
  resolvedDid: string
  sessionId: string
}) {
  getDb().prepare(`
    UPDATE oauth_login_attempts
    SET status = 'completed',
        completed_at = ?,
        resolved_did = ?,
        session_id = ?
    WHERE id = ? AND status = 'pending'
  `).run(nowIso(), input.resolvedDid, input.sessionId, input.id)
}

export function failOAuthLoginAttempt(id: string, errorCode: string) {
  getDb().prepare(`
    UPDATE oauth_login_attempts
    SET status = 'failed',
        failed_at = ?,
        error_code = ?
    WHERE id = ? AND status = 'pending'
  `).run(nowIso(), errorCode, id)
}

export function expireOAuthLoginAttempt(id: string) {
  getDb().prepare(`
    UPDATE oauth_login_attempts
    SET status = 'expired',
        failed_at = ?,
        error_code = 'OAUTH_ATTEMPT_EXPIRED'
    WHERE id = ? AND status = 'pending'
  `).run(nowIso(), id)
}
