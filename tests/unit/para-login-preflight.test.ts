import { it } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Database from 'better-sqlite3'
import { checkLoginConfiguration, checkLoginEndpoints, type LoginPreflightConfig } from '../../src/services/paraLoginPreflight.js'

function fixture(run: (config: LoginPreflightConfig) => void) {
  const directory = mkdtempSync(join(tmpdir(), 'm8-preflight-'))
  const databasePath = join(directory, 'broker.db')
  const db = new Database(databasePath)
  db.exec(`
    CREATE TABLE migrations (name TEXT);
    INSERT INTO migrations VALUES ('040_oauth_exchange_binding.sql'), ('041_oauth_code_binding_retention.sql');
    CREATE TABLE oauth_login_attempts (id TEXT, exchange_challenge TEXT);
    CREATE TABLE oauth_exchange_codes (id TEXT, exchange_challenge TEXT);
  `)
  db.close()
  try {
    run({
      serviceUrl: 'https://m8.example', webOrigin: 'https://para.example',
      allowlist: 'im8://oauth/callback,para://m8-auth,https://para.example/m8-auth',
      corsOrigin: 'https://para.example', databasePath,
      handoffEnabled: true, bootstrapEnabled: false, featureFlagsLoaded: true, local: false,
    })
  } finally { rmSync(directory, { recursive: true, force: true }) }
}

it('accepts paired configuration and inspects migrations without changing the schema', () => {
  fixture((config) => {
    assert.ok(checkLoginConfiguration(config).every((check) => check.passed))
    const db = new Database(config.databasePath, { readonly: true })
    assert.equal((db.prepare('SELECT count(*) AS n FROM migrations').get() as { n: number }).n, 2)
    assert.equal((db.prepare('SELECT count(*) AS n FROM oauth_login_attempts').get() as { n: number }).n, 0)
    db.close()
  })
})

it('blocks stale callbacks, development bootstrap, failed flag initialization and wildcard CORS', () => {
  fixture((config) => {
    const checks = checkLoginConfiguration({ ...config,
      allowlist: 'para://m8/oauth-callback', corsOrigin: '*',
      bootstrapEnabled: true, handoffEnabled: false, featureFlagsLoaded: false,
    })
    assert.deepEqual(checks.filter((check) => !check.passed).map((check) => check.name), [
      'feature-flags-loaded', 'handoff-enabled', 'bootstrap-disabled', 'mobile-callback', 'web-callback', 'web-cors-config',
    ])
  })
})

it('requires recorded migrations and actual binding columns; never creates a missing database', () => {
  fixture((config) => {
    const db = new Database(config.databasePath)
    db.exec('DELETE FROM migrations; ALTER TABLE oauth_exchange_codes DROP COLUMN exchange_challenge;')
    db.close()
    assert.deepEqual(checkLoginConfiguration(config).filter((check) => !check.passed).map((check) => check.name), [
      '040_oauth_exchange_binding.sql', '041_oauth_code_binding_retention.sql',
    ])
    const missing = `${config.databasePath}.missing`
    assert.ok(checkLoginConfiguration({ ...config, databasePath: missing }).some((check) => check.name === 'database-readable' && !check.passed))
    assert.equal(existsSync(missing), false)
  })
})

it('permits HTTP loopback only with --local and rejects credentials, paths and nonloopback HTTP', () => {
  fixture((config) => {
    const local = { ...config, serviceUrl: 'http://localhost:8787', webOrigin: 'http://127.0.0.1:8081',
      corsOrigin: 'http://127.0.0.1:8081', allowlist: 'para://m8-auth,http://127.0.0.1:8081/m8-auth', local: true }
    assert.ok(checkLoginConfiguration(local).every((check) => check.passed))
    assert.ok(checkLoginConfiguration({ ...local, local: false }).some((check) => !check.passed))
    for (const serviceUrl of ['http://machine.local:8787', 'https://secret@broker.example', 'https://broker.example/base', 'https://broker.example/']) {
      const checks = checkLoginConfiguration({ ...config, serviceUrl })
      assert.equal(checks.find((check) => check.name === 'broker-origin')?.passed, false)
      assert.equal(JSON.stringify(checks).includes('secret@'), false)
    }
  })
})

const endpointConfig: LoginPreflightConfig = {
  serviceUrl: 'https://m8.example', webOrigin: 'https://para.example', local: false,
  allowlist: '', corsOrigin: '', databasePath: '', handoffEnabled: true, bootstrapEnabled: false, featureFlagsLoaded: true,
}

it('probes metadata, exact CORS and callback HTML with only unauthenticated GET/OPTIONS requests', async () => {
  const methods: string[] = []
  const request: typeof fetch = async (url, init) => {
    methods.push(init?.method ?? 'GET')
    assert.equal(init?.redirect, 'error')
    assert.equal(init?.body, undefined)
    assert.equal(new Headers(init?.headers).has('authorization'), false)
    if (String(url).endsWith('/health')) return Response.json({ status: 'ok' })
    if (String(url).endsWith('metadata.json')) return Response.json({
      client_id: 'https://m8.example/oauth-client-metadata.json',
      redirect_uris: ['https://m8.example/v1/sessions/oauth/callback'],
      grant_types: ['authorization_code', 'refresh_token'], dpop_bound_access_tokens: true,
    })
    if (init?.method === 'OPTIONS') return new Response(null, { status: 204, headers: {
      'access-control-allow-origin': 'https://para.example',
      'access-control-allow-methods': 'GET, POST',
      'access-control-allow-headers': 'content-type, Authorization, x-m8-session-id',
    } })
    return new Response('<html></html>', { headers: { 'content-type': 'text/html; charset=utf-8' } })
  }
  assert.ok((await checkLoginEndpoints(endpointConfig, request)).every((check) => check.passed))
  assert.deepEqual(methods, ['GET', 'GET', 'OPTIONS', 'GET'])
})

it('reports mismatched deployed metadata, wildcard CORS and missing callback routing without echoing response bodies', async () => {
  const request: typeof fetch = async (url, init) => {
    if (String(url).endsWith('/health')) throw new Error('sensitive-network-detail')
    if (String(url).endsWith('metadata.json')) return Response.json({ client_id: 'https://old.example' })
    if (init?.method === 'OPTIONS') return new Response(null, { headers: { 'access-control-allow-origin': '*' } })
    return new Response('sensitive-server-detail', { status: 404 })
  }
  const checks = await checkLoginEndpoints(endpointConfig, request)
  assert.equal(checks.filter((check) => !check.passed).length, 4)
  assert.equal(JSON.stringify(checks).includes('sensitive-'), false)
})
