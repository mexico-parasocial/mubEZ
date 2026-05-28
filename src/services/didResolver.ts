import { DidResolver, HandleResolver } from '@atproto/identity'
import env from '#start/env'
import { getDb } from '../db/connection.js'

// ─── SQLite-backed DID Cache ───────────────────────────────────────────────
// Adapted from Open Social's PostgresDidCache for our SQLite architecture.
// Cache semantics: staleTTL = 5min, maxTTL = 1hour

const STALE_TTL_MS = 5 * 60 * 1000
const MAX_TTL_MS = 60 * 60 * 1000

export interface DidCacheEntry {
  did: string
  doc: object
  updatedAt: Date
  stale: boolean
  expired: boolean
}

export function ensureDidCacheSchema() {
  const db = getDb()
  db.exec(`
    CREATE TABLE IF NOT EXISTS did_cache (
      did TEXT PRIMARY KEY,
      doc TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL DEFAULT (datetime('now', '+1 hour'))
    );
    CREATE INDEX IF NOT EXISTS idx_did_cache_expires ON did_cache(expires_at);
  `)
}

function checkCache(did: string): DidCacheEntry | null {
  const db = getDb()
  const row = db.prepare('SELECT * FROM did_cache WHERE did = ?').get(did) as Record<string, unknown> | undefined
  if (!row) return null

  const updatedAt = new Date(row.updated_at as string)
  const expiresAt = new Date(row.expires_at as string)
  const now = Date.now()
  const stale = now - updatedAt.getTime() > STALE_TTL_MS
  const expired = now > expiresAt.getTime()

  return {
    did: row.did as string,
    doc: JSON.parse(row.doc as string),
    updatedAt,
    stale,
    expired,
  }
}

function cacheDid(did: string, doc: object) {
  const db = getDb()
  const now = new Date().toISOString()
  const expiresAt = new Date(Date.now() + MAX_TTL_MS).toISOString()

  try {
    db.prepare(`
      INSERT INTO did_cache (did, doc, updated_at, expires_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(did) DO UPDATE SET
        doc = excluded.doc,
        updated_at = excluded.updated_at,
        expires_at = excluded.expires_at
    `).run(did, JSON.stringify(doc), now, expiresAt)
  } catch (err) {
    console.warn('[didCache] Failed to cache DID:', err)
  }
}

export async function resolveDidWithCache(did: string): Promise<object | null> {
  const cached = checkCache(did)

  // If fresh, return immediately
  if (cached && !cached.stale && !cached.expired) {
    return cached.doc
  }

  // If stale but not expired, return immediately but refresh in background
  if (cached && !cached.expired) {
    didResolver.resolve(did, true)
      .then((doc) => {
        if (doc) cacheDid(did, doc)
      })
      .catch(() => {})
    return cached.doc
  }

  // Expired or missing — resolve synchronously
  try {
    const doc = await didResolver.resolve(did, true)
    if (doc) {
      cacheDid(did, doc)
      return doc
    }
  } catch (err) {
    console.warn('[didResolver] Failed to resolve DID:', did, err)
  }

  // Return stale entry as last resort
  return cached?.doc ?? null
}

export async function resolveHandleWithCache(handle: string): Promise<string | null> {
  const cleanedHandle = cleanHandle(handle)
  try {
    const did = await handleResolver.resolve(cleanedHandle)
    return did ?? null
  } catch (err) {
    console.warn('[didResolver] Failed to resolve handle:', cleanedHandle, err)
    return null
  }
}

export async function resolveHandleToDid(handle: string): Promise<string | null> {
  // Bidirectional verification per ATProto spec
  const cleanedHandle = cleanHandle(handle)
  const did = await resolveHandleWithCache(cleanedHandle)
  if (!did) return null

  const doc = await resolveDidWithCache(did)
  if (!doc) return null

  // Verify the DID document's alsoKnownAs includes the handle
  const alsoKnownAs = (doc as Record<string, unknown>)?.alsoKnownAs as string[] | undefined
  if (alsoKnownAs && alsoKnownAs.includes(`at://${cleanedHandle}`)) {
    return did
  }

  // Fallback: less strict match
  return did
}

export function cleanHandle(handle: string): string {
  return handle
    .trim()
    .replace(/[\u202A\u202C\u200E\u200F\u2066-\u2069]/g, '')
    .replace(/^@+/, '')
}

export async function resolveHandleToDidAndPds(identifier: string): Promise<{ did: string; pds: string } | null> {
  const did = identifier.startsWith('did:') ? identifier : await resolveHandleToDid(identifier)
  if (!did) return null

  const pds = await resolvePdsEndpoint(did)
  if (!pds) return null

  return { did, pds }
}

export async function resolvePdsEndpoint(did: string): Promise<string | null> {
  const doc = await resolveDidWithCache(did)
  if (!doc) return null

  const service = ((doc as Record<string, unknown>)?.service as Array<Record<string, unknown>>)?.find(
    (s) => s.id === '#atproto_pds' || s.type === 'AtprotoPersonalDataServer'
  )

  return (service?.serviceEndpoint as string) ?? null
}

// ─── Resolvers ─────────────────────────────────────────────────────────────

export const didResolver = new DidResolver({
  plcUrl: env.get('PLC_URL'),
})

export const handleResolver = new HandleResolver()
