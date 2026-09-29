import { describe, it, before, after, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-did-resolution-'))
process.env.DATABASE_PATH = join(tmpDir, 'did-resolution.db')

/*
 * Handle → DID resolution for authentication must be bidirectional (atproto
 * handle spec), resolved fresh, and fail closed; cached documents never
 * rescue an outage on the security paths.
 */

const ALICE_DID = 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa'
const PDS = 'https://pds.example.com'

function doc(did: string, alsoKnownAs?: string[]) {
  return {
    id: did,
    ...(alsoKnownAs ? { alsoKnownAs } : {}),
    service: [{ id: '#atproto_pds', type: 'AtprotoPersonalDataServer', serviceEndpoint: PDS }],
  }
}

describe('DID and handle resolution', () => {
  let resolver: typeof import('../../src/services/didResolver.js')
  let session: typeof import('../../src/services/sessionService.js')
  let getDb: typeof import('../../src/db/connection.js').getDb
  let closeDb: typeof import('../../src/db/connection.js').closeDb
  let forceRefreshCalls: boolean[] = []

  function useNetwork(opts: {
    handles?: Record<string, string | Error>
    docs?: Record<string, object | Error | null>
  }) {
    forceRefreshCalls = []
    resolver.setIdentityResolversForTesting({
      handle: {
        async resolve(handle) {
          const entry = opts.handles?.[handle]
          if (entry instanceof Error) throw entry
          return entry
        },
      },
      did: {
        async resolve(did, forceRefresh) {
          forceRefreshCalls.push(forceRefresh === true)
          const entry = opts.docs?.[did]
          if (entry instanceof Error) throw entry
          return entry ?? null
        },
      },
    })
  }

  function cacheRow(did: string, document: object, ageMs: number, ttlMs = 60 * 60 * 1000) {
    const updatedAt = new Date(Date.now() - ageMs)
    getDb().prepare(`
      INSERT INTO did_cache (did, doc, updated_at, expires_at) VALUES (?, ?, ?, ?)
      ON CONFLICT(did) DO UPDATE SET doc = excluded.doc, updated_at = excluded.updated_at, expires_at = excluded.expires_at
    `).run(did, JSON.stringify(document), updatedAt.toISOString(), new Date(updatedAt.getTime() + ttlMs).toISOString())
  }

  before(async () => {
    const conn = await import('../../src/db/connection.js')
    getDb = conn.getDb
    closeDb = conn.closeDb
    const { ensureSchema, runMigrations } = await import('../../src/db/migrate.js')
    ensureSchema()
    runMigrations()
    resolver = await import('../../src/services/didResolver.js')
    session = await import('../../src/services/sessionService.js')
  })

  afterEach(() => {
    resolver.setIdentityResolversForTesting()
    getDb().prepare('DELETE FROM did_cache').run()
  })

  after(() => closeDb())

  it('accepts a valid bidirectional handle link, normalizing case', async () => {
    useNetwork({
      handles: { 'alice.example.com': ALICE_DID },
      docs: { [ALICE_DID]: doc(ALICE_DID, ['at://Alice.Example.com']) },
    })

    const verified = await resolver.resolveVerifiedHandle('@Alice.Example.COM')
    assert.equal(verified.did, ALICE_DID)
    assert.equal(verified.handle, 'alice.example.com')
    assert.deepEqual(forceRefreshCalls, [true])

    const login = await session.resolveLoginIdentity('alice.example.com', { allowUnresolvedDevIdentity: false })
    assert.deepEqual(login, { did: ALICE_DID, handle: 'alice.example.com', pdsEndpoint: PDS })
  })

  it('rejects a DID document with no alsoKnownAs', async () => {
    useNetwork({
      handles: { 'alice.example.com': ALICE_DID },
      docs: { [ALICE_DID]: doc(ALICE_DID) },
    })

    await assert.rejects(resolver.resolveVerifiedHandle('alice.example.com'), { code: 'HANDLE_MISMATCH' })
    assert.equal(await resolver.resolveHandleToDid('alice.example.com'), null)
  })

  it('rejects a mismatched alsoKnownAs, judging only the first valid handle', async () => {
    useNetwork({
      handles: { 'alice.example.com': ALICE_DID },
      docs: { [ALICE_DID]: doc(ALICE_DID, ['at://mallory.example.com', 'at://alice.example.com']) },
    })
    await assert.rejects(resolver.resolveVerifiedHandle('alice.example.com'), { code: 'HANDLE_MISMATCH' })

    // Syntactically invalid entries are skipped, not treated as the claim.
    useNetwork({
      handles: { 'alice.example.com': ALICE_DID },
      docs: { [ALICE_DID]: doc(ALICE_DID, ['https://alice.example.com', 'at://not a handle', 'at://alice.example.com']) },
    })
    assert.equal((await resolver.resolveVerifiedHandle('alice.example.com')).did, ALICE_DID)

    // A document whose id is some other DID does not count.
    useNetwork({
      handles: { 'alice.example.com': ALICE_DID },
      docs: { [ALICE_DID]: doc('did:plc:bbbbbbbbbbbbbbbbbbbbbbbb', ['at://alice.example.com']) },
    })
    await assert.rejects(resolver.resolveVerifiedHandle('alice.example.com'), { code: 'DID_NOT_FOUND' })
  })

  it('does not rescue a disowned handle with the development fallback', async () => {
    useNetwork({
      handles: { 'alice.example.com': ALICE_DID },
      docs: { [ALICE_DID]: doc(ALICE_DID, ['at://someone-else.example.com']) },
    })
    await assert.rejects(
      session.resolveLoginIdentity('alice.example.com', { allowUnresolvedDevIdentity: true }),
      { code: 'HANDLE_MISMATCH' },
    )
  })

  it('ignores a fresh cache entry that still claims a handle the DID has dropped', async () => {
    // Cached 30 seconds ago, before the account changed its handle.
    cacheRow(ALICE_DID, doc(ALICE_DID, ['at://alice.example.com']), 30 * 1000)
    useNetwork({
      handles: { 'alice.example.com': ALICE_DID }, // stale DNS / well-known still points here
      docs: { [ALICE_DID]: doc(ALICE_DID, ['at://alice-new.example.com']) },
    })

    await assert.rejects(resolver.resolveVerifiedHandle('alice.example.com'), { code: 'HANDLE_MISMATCH' })
    assert.deepEqual(forceRefreshCalls, [true])

    // The fresh document replaced the cached one.
    const cached = getDb().prepare('SELECT doc FROM did_cache WHERE did = ?').get(ALICE_DID) as { doc: string }
    assert.deepEqual(JSON.parse(cached.doc).alsoKnownAs, ['at://alice-new.example.com'])
  })

  it('fails closed when the resolver is unavailable, whatever the cache holds', async () => {
    useNetwork({ handles: { 'alice.example.com': new Error('DNS timeout') } })
    await assert.rejects(resolver.resolveVerifiedHandle('alice.example.com'), { code: 'RESOLVER_UNAVAILABLE' })
    await assert.rejects(
      session.resolveLoginIdentity('alice.example.com', { allowUnresolvedDevIdentity: false }),
      { code: 'RESOLVER_UNAVAILABLE' },
    )

    // Handle resolves but PLC is down; a matching cached document is not used.
    cacheRow(ALICE_DID, doc(ALICE_DID, ['at://alice.example.com']), 10 * 1000)
    useNetwork({
      handles: { 'alice.example.com': ALICE_DID },
      docs: { [ALICE_DID]: new Error('plc.directory 503') },
    })
    await assert.rejects(resolver.resolveVerifiedHandle('alice.example.com'), { code: 'RESOLVER_UNAVAILABLE' })
  })

  it('never serves an expired document, and bounds security reads to five minutes', async () => {
    useNetwork({ docs: { [ALICE_DID]: new Error('plc.directory 503') } })

    // Expired: the routing/display path returns null instead of the old document.
    cacheRow(ALICE_DID, doc(ALICE_DID, ['at://alice.example.com']), 2 * 60 * 60 * 1000)
    assert.equal(await resolver.resolveDidWithCache(ALICE_DID), null)
    assert.equal(await resolver.resolvePdsEndpoint(ALICE_DID), null)

    // Stale but unexpired (10 minutes): routing may use it, security may not.
    cacheRow(ALICE_DID, doc(ALICE_DID, ['at://alice.example.com']), 10 * 60 * 1000)
    assert.ok(await resolver.resolveDidWithCache(ALICE_DID))
    assert.equal(await resolver.resolveDidForSecurity(ALICE_DID), null)

    // Within five minutes the security path may use the cache.
    cacheRow(ALICE_DID, doc(ALICE_DID, ['at://alice.example.com']), 60 * 1000)
    assert.ok(await resolver.resolveDidForSecurity(ALICE_DID))
  })

  it('logs in by DID directly, recording the handle only when it verifies', async () => {
    useNetwork({
      handles: { 'alice.example.com': ALICE_DID },
      docs: { [ALICE_DID]: doc(ALICE_DID, ['at://alice.example.com']) },
    })
    assert.deepEqual(
      await session.resolveLoginIdentity(ALICE_DID, { allowUnresolvedDevIdentity: false }),
      { did: ALICE_DID, handle: 'alice.example.com', pdsEndpoint: PDS },
    )

    // The document claims a handle that points elsewhere: DID stands, handle does not.
    useNetwork({
      handles: { 'alice.example.com': 'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb' },
      docs: { [ALICE_DID]: doc(ALICE_DID, ['at://alice.example.com']) },
    })
    assert.deepEqual(
      await session.resolveLoginIdentity(ALICE_DID, { allowUnresolvedDevIdentity: false }),
      { did: ALICE_DID, handle: ALICE_DID, pdsEndpoint: PDS },
    )

    // Directory down: production refuses, development accepts without a document.
    useNetwork({ docs: { [ALICE_DID]: new Error('plc.directory 503') } })
    await assert.rejects(
      session.resolveLoginIdentity(ALICE_DID, { allowUnresolvedDevIdentity: false }),
      { code: 'RESOLVER_UNAVAILABLE' },
    )
    assert.deepEqual(
      await session.resolveLoginIdentity(ALICE_DID, { allowUnresolvedDevIdentity: true }),
      { did: ALICE_DID, handle: ALICE_DID, pdsEndpoint: null },
    )

    // Unknown DID in production.
    useNetwork({ docs: {} })
    await assert.rejects(
      session.resolveLoginIdentity(ALICE_DID, { allowUnresolvedDevIdentity: false }),
      { code: 'DID_NOT_FOUND' },
    )
  })

  it('rejects syntactically invalid handles before any network call', async () => {
    useNetwork({})
    for (const bad of ['localhost', 'alice..example.com', 'alice.123', '-alice.example.com', 'al ice.example.com']) {
      await assert.rejects(resolver.resolveVerifiedHandle(bad), { code: 'INVALID_HANDLE' }, bad)
    }
    assert.deepEqual(forceRefreshCalls, [])
  })
})
