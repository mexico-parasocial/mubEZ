import { DidResolver, HandleResolver } from '@atproto/identity'
import env from '#start/env'
import { getDb } from '../db/connection.js'

// ─── SQLite-backed DID Cache ───────────────────────────────────────────────
// Adapted from Open Social's PostgresDidCache for our SQLite architecture.
// Cache semantics: staleTTL = 5min, maxTTL = 1hour
//
// Three read paths, by how much the caller may trust an old document:
//   - resolveDidFresh: always hits the directory, fails closed. Authentication
//     decisions (handle → DID login) use this.
//   - resolveDidForSecurity: a cached document younger than STALE_TTL (under
//     the 10 minutes the atproto OAuth spec recommends for auth flows), else
//     fresh; fails closed. Signature and key checks use this.
//   - resolveDidWithCache: stale-while-revalidate up to MAX_TTL, for routing
//     and display. It never returns an expired document: when the directory
//     is down and the entry has expired, it returns null.

const STALE_TTL_MS = 5 * 60 * 1000
const MAX_TTL_MS = 60 * 60 * 1000

export interface DidCacheEntry {
  did: string
  doc: object
  updatedAt: Date
  stale: boolean
  expired: boolean
}

export type IdentityResolutionErrorCode =
  | 'INVALID_HANDLE'
  | 'INVALID_DID'
  | 'HANDLE_NOT_FOUND'
  | 'DID_NOT_FOUND'
  | 'HANDLE_MISMATCH'
  | 'RESOLVER_UNAVAILABLE'

export class IdentityResolutionError extends Error {
  constructor(
    message: string,
    public readonly code: IdentityResolutionErrorCode,
  ) {
    super(message)
  }
}

type DidDocumentResolver = { resolve(did: string, forceRefresh?: boolean): Promise<unknown> }
type HandleToDidResolver = { resolve(handle: string): Promise<string | undefined | null> }

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
  const stale = !(now - updatedAt.getTime() <= STALE_TTL_MS)
  const expired = !(now <= expiresAt.getTime())

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

/**
 * Resolves a DID document from the directory, bypassing the cache, and caches
 * the result. Throws IdentityResolutionError on outage, absence, or a document
 * whose id is not the requested DID. Never falls back to a cached document.
 */
export async function resolveDidFresh(did: string): Promise<Record<string, unknown>> {
  if (!isValidDid(did)) {
    throw new IdentityResolutionError(`Invalid DID: ${did}`, 'INVALID_DID')
  }

  let doc: unknown
  try {
    doc = await resolvers.did.resolve(did, true)
  } catch (err) {
    throw new IdentityResolutionError(
      `DID resolution unavailable for ${did}: ${err instanceof Error ? err.message : String(err)}`,
      'RESOLVER_UNAVAILABLE',
    )
  }
  if (!doc || typeof doc !== 'object') {
    throw new IdentityResolutionError(`DID not found: ${did}`, 'DID_NOT_FOUND')
  }
  if ((doc as Record<string, unknown>).id !== did) {
    throw new IdentityResolutionError(`DID document id does not match ${did}`, 'DID_NOT_FOUND')
  }

  cacheDid(did, doc)
  return doc as Record<string, unknown>
}

/**
 * For key and signature checks: a cached document no older than STALE_TTL,
 * otherwise a fresh resolution. Fails closed (null) when the directory is
 * unavailable and the cached document is older than that.
 */
export async function resolveDidForSecurity(did: string): Promise<object | null> {
  const cached = checkCache(did)
  if (cached && !cached.stale && !cached.expired) {
    return cached.doc
  }
  try {
    return await resolveDidFresh(did)
  } catch (err) {
    console.warn('[didResolver] Failed to resolve DID:', did, err)
    return null
  }
}

/**
 * Stale-while-revalidate resolution for routing and display. Returns null
 * rather than an expired document when the directory is unavailable. Do not
 * use for authentication or key checks; see resolveDidFresh and
 * resolveDidForSecurity.
 */
export async function resolveDidWithCache(did: string): Promise<object | null> {
  const cached = checkCache(did)

  // If fresh, return immediately
  if (cached && !cached.stale && !cached.expired) {
    return cached.doc
  }

  // If stale but not expired, return immediately but refresh in background
  if (cached && !cached.expired) {
    resolveDidFresh(did).catch(() => {})
    return cached.doc
  }

  // Expired or missing — resolve synchronously; an expired entry is not reused
  try {
    return await resolveDidFresh(did)
  } catch (err) {
    console.warn('[didResolver] Failed to resolve DID:', did, err)
    return null
  }
}

export async function resolveHandleWithCache(handle: string): Promise<string | null> {
  const cleanedHandle = cleanHandle(handle)
  try {
    const did = await resolvers.handle.resolve(cleanedHandle)
    return did ?? null
  } catch (err) {
    console.warn('[didResolver] Failed to resolve handle:', cleanedHandle, err)
    return null
  }
}

/**
 * Resolves a handle to a DID for an authentication decision, per the AT
 * Protocol handle spec: the handle must resolve to a DID, and that DID's
 * current document (resolved fresh, never from cache) must claim the same
 * handle as the first syntactically valid `at://` entry in `alsoKnownAs`.
 * Throws IdentityResolutionError on any failure, including resolver outage.
 */
export async function resolveVerifiedHandle(
  handle: string
): Promise<{ did: string; handle: string; doc: Record<string, unknown> }> {
  const normalized = normalizeHandle(handle)
  if (!normalized) {
    throw new IdentityResolutionError(`Invalid handle: ${handle}`, 'INVALID_HANDLE')
  }

  let did: string | null | undefined
  try {
    did = await resolvers.handle.resolve(normalized)
  } catch (err) {
    throw new IdentityResolutionError(
      `Handle resolution unavailable for ${normalized}: ${err instanceof Error ? err.message : String(err)}`,
      'RESOLVER_UNAVAILABLE',
    )
  }
  if (!did) {
    throw new IdentityResolutionError(`Handle does not resolve to a DID: ${normalized}`, 'HANDLE_NOT_FOUND')
  }

  const doc = await resolveDidFresh(did)
  if (claimedHandle(doc) !== normalized) {
    throw new IdentityResolutionError(
      `DID document for ${did} does not claim handle ${normalized}`,
      'HANDLE_MISMATCH',
    )
  }

  return { did, handle: normalized, doc }
}

/** Fail-closed wrapper: the bidirectionally verified DID, or null. */
export async function resolveHandleToDid(handle: string): Promise<string | null> {
  try {
    return (await resolveVerifiedHandle(handle)).did
  } catch (err) {
    console.warn('[didResolver] Handle not verified:', cleanHandle(handle), err instanceof Error ? err.message : err)
    return null
  }
}

export function cleanHandle(handle: string): string {
  return handle
    .trim()
    .replace(/[‪‬‎‏⁦-⁩]/g, '')
    .replace(/^@+/, '')
}

// https://atproto.com/specs/handle — ASCII only, 2+ labels, 253 chars max,
// the last label (TLD) may not start with a digit.
const HANDLE_REGEX =
  /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/

/** Lowercases a cleaned handle; null when it is not syntactically valid. */
export function normalizeHandle(handle: string): string | null {
  const cleaned = cleanHandle(handle).toLowerCase()
  if (cleaned.length > 253 || !HANDLE_REGEX.test(cleaned)) return null
  return cleaned
}

/**
 * The handle a DID document claims: the first syntactically valid `at://`
 * handle in `alsoKnownAs`, normalized to lowercase (atproto DID spec). Later
 * entries are ignored. Null when the document claims none.
 */
export function claimedHandle(doc: unknown): string | null {
  const aka = (doc as Record<string, unknown> | null)?.alsoKnownAs
  if (!Array.isArray(aka)) return null
  for (const entry of aka) {
    if (typeof entry !== 'string' || !entry.startsWith('at://')) continue
    const handle = normalizeHandle(entry.slice('at://'.length))
    if (handle && handle === entry.slice('at://'.length).toLowerCase()) return handle
  }
  return null
}

export function isValidDid(did: string): boolean {
  return /^did:(plc:[a-z2-7]{24}|web:[a-zA-Z0-9.%:-]+)$/.test(did)
}

export async function resolveHandleToDidAndPds(identifier: string): Promise<{ did: string; pds: string } | null> {
  const did = identifier.startsWith('did:') ? identifier : await resolveHandleToDid(identifier)
  if (!did) return null

  const pds = await resolvePdsEndpoint(did)
  if (!pds) return null

  return { did, pds }
}

export function pdsEndpointFromDocument(doc: object): string | null {
  const service = ((doc as Record<string, unknown>)?.service as Array<Record<string, unknown>>)?.find(
    (s) => s.id === '#atproto_pds' || s.type === 'AtprotoPersonalDataServer'
  )

  return (service?.serviceEndpoint as string) ?? null
}

export async function resolvePdsEndpoint(did: string): Promise<string | null> {
  const doc = await resolveDidWithCache(did)
  if (!doc) return null
  return pdsEndpointFromDocument(doc)
}

// ─── Resolvers ─────────────────────────────────────────────────────────────

export const didResolver = new DidResolver({
  plcUrl: env.get('PLC_URL'),
})

export const handleResolver = new HandleResolver()

let resolvers: { did: DidDocumentResolver; handle: HandleToDidResolver } = {
  did: didResolver,
  handle: handleResolver,
}

/** Test seam: swap the network resolvers. Call with no argument to restore. */
export function setIdentityResolversForTesting(
  next?: Partial<{ did: DidDocumentResolver; handle: HandleToDidResolver }>
) {
  resolvers = {
    did: next?.did ?? didResolver,
    handle: next?.handle ?? handleResolver,
  }
}
