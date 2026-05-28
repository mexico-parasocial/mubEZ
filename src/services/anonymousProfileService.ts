import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { getDb } from '../db/connection.js'

export interface AnonymousProfile {
  id: string
  displayName: string
  avatarSeed: string
  createdAt: string
}

export function createAnonymousProfile(sessionId: string, displayNamePrefix = 'Ciudadano'): AnonymousProfile {
  const db = getDb()
  const existing = db.prepare(
    'SELECT id, display_name, avatar_seed, created_at FROM anonymous_profiles WHERE session_id = ?'
  ).get(sessionId) as { id: string; display_name: string; avatar_seed: string; created_at: string } | undefined

  if (existing) {
    return {
      id: existing.id,
      displayName: existing.display_name,
      avatarSeed: existing.avatar_seed,
      createdAt: existing.created_at,
    }
  }

  const secret = randomBytes(32).toString('hex')
  const displayName = `${displayNamePrefix} #${secret.slice(0, 6).toUpperCase()}`
  const avatarSeed = randomBytes(16).toString('hex')
  const id = `anon-${randomUUID()}`

  db.prepare(`
    INSERT INTO anonymous_profiles (id, session_id, display_name, avatar_seed, nullifier_secret, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    id,
    sessionId,
    displayName,
    avatarSeed,
    createHash('sha256').update(secret).digest('hex'),
    new Date().toISOString(),
  )

  return { id, displayName, avatarSeed, createdAt: new Date().toISOString() }
}

export function deleteAnonymousProfile(sessionId: string): void {
  const db = getDb()
  db.prepare('DELETE FROM anonymous_profiles WHERE session_id = ?').run(sessionId)
}

export function getAnonymousProfile(sessionId: string): AnonymousProfile | null {
  const db = getDb()
  const row = db.prepare(
    'SELECT id, display_name, avatar_seed, created_at FROM anonymous_profiles WHERE session_id = ?'
  ).get(sessionId) as { id: string; display_name: string; avatar_seed: string; created_at: string } | undefined

  if (!row) return null
  return {
    id: row.id,
    displayName: row.display_name,
    avatarSeed: row.avatar_seed,
    createdAt: row.created_at,
  }
}
