import Database from 'better-sqlite3'
import { resolveOAuthHandoff } from './oauthHandoff.js'

export interface LoginPreflightConfig {
  serviceUrl: string
  webOrigin: string
  allowlist: string
  corsOrigin: string
  databasePath: string
  handoffEnabled: boolean
  bootstrapEnabled: boolean
  featureFlagsLoaded: boolean
  local: boolean
}

export interface PreflightCheck {
  name: string
  passed: boolean
  detail: string
}

function origin(value: string, local: boolean): string | null {
  try {
    const url = new URL(value)
    if (url.username || url.password || url.search || url.hash || url.pathname !== '/') return null
    if (url.protocol !== 'https:' && !(
      local && url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
    )) return null
    return url.origin
  } catch {
    return null
  }
}

/** No app boot, database creation/migration, session start or credential issuance. */
export function checkLoginConfiguration(config: LoginPreflightConfig): PreflightCheck[] {
  const checks: PreflightCheck[] = []
  const add = (name: string, passed: boolean, detail: string) => checks.push({ name, passed, detail })
  const broker = origin(config.serviceUrl, config.local)
  const web = origin(config.webOrigin, config.local)
  add('broker-origin', broker !== null && broker === config.serviceUrl, 'SERVICE_URL must be a canonical HTTPS origin without a trailing slash; --local permits loopback HTTP.')
  add('web-origin', web !== null, 'Select the actual PARA web HTTPS origin; --local permits loopback HTTP.')
  add('feature-flags-loaded', config.featureFlagsLoaded, 'Configured GrowthBook initialization must succeed.')
  add('handoff-enabled', config.handoffEnabled, 'Enable m8:auth:oauth_mobile_handoff.')
  add('bootstrap-disabled', !config.bootstrapEnabled, 'Disable m8:auth:dev_token_bootstrap for real-provider acceptance.')
  for (const [platform, callback] of [['mobile', 'para://m8-auth'], ['web', web ? `${web}/m8-auth` : '']] as const) {
    let accepted = false
    try {
      accepted = resolveOAuthHandoff(platform, callback, true, config.allowlist) === callback
    } catch { /* Report configuration errors without echoing potentially sensitive input. */ }
    add(`${platform}-callback`, accepted, 'OAUTH_RETURN_TO_ALLOWLIST must contain the exact selected callback.')
  }
  const allowedOrigins = config.corsOrigin.split(',').map((value) => value.trim())
  add('web-cors-config', web !== null && allowedOrigins.includes(web) && !allowedOrigins.includes('*'), 'CORS_ORIGIN must explicitly include the selected PARA origin, without a wildcard.')

  let db: Database.Database | undefined
  try {
    db = new Database(config.databasePath, { readonly: true, fileMustExist: true })
    for (const [migration, table] of [
      ['040_oauth_exchange_binding.sql', 'oauth_login_attempts'],
      ['041_oauth_code_binding_retention.sql', 'oauth_exchange_codes'],
    ]) {
      const recorded = Boolean(db.prepare('SELECT 1 FROM migrations WHERE name = ?').get(migration))
      const columns = db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[]
      add(migration, recorded && columns.some((column) => column.name === 'exchange_challenge'), 'Apply the paired broker migration using the normal runner after a database backup.')
    }
  } catch {
    add('database-readable', false, 'The selected existing database/schema could not be inspected read-only; no database was created or changed.')
  } finally {
    db?.close()
  }
  return checks
}

/** Public GETs and a CORS OPTIONS probe only. Never sends a DID or a bearer token. */
export async function checkLoginEndpoints(
  config: LoginPreflightConfig,
  request: typeof fetch = fetch,
): Promise<PreflightCheck[]> {
  const checks: PreflightCheck[] = []
  const broker = origin(config.serviceUrl, config.local)
  const web = origin(config.webOrigin, config.local)
  if (!broker || broker !== config.serviceUrl || !web) return checks
  const probe = async (name: string, run: () => Promise<boolean>, detail: string) => {
    try { checks.push({ name, passed: await run(), detail }) }
    catch { checks.push({ name, passed: false, detail }) }
  }
  const get = (url: string, init?: RequestInit) => request(url, {
    ...init, redirect: 'error', signal: AbortSignal.timeout(5000),
  })
  await probe('broker-health', async () => {
    const response = await get(`${broker}/v1/health`)
    return response.ok && (await response.json() as { status?: unknown }).status === 'ok'
  }, 'The selected broker must return healthy JSON directly.')
  await probe('oauth-metadata', async () => {
    const response = await get(`${broker}/oauth-client-metadata.json`)
    if (!response.ok) return false
    const metadata = await response.json() as Record<string, unknown>
    const callbackBroker = broker.replace(/^http:\/\/localhost:/, 'http://127.0.0.1:')
    const loopback = callbackBroker.startsWith('http://127.0.0.1:')
    return metadata.client_id === (loopback ? 'http://localhost' : `${broker}/oauth-client-metadata.json`) &&
      Array.isArray(metadata.redirect_uris) && metadata.redirect_uris.includes(`${callbackBroker}/v1/sessions/oauth/callback`) &&
      Array.isArray(metadata.grant_types) && metadata.grant_types.includes('authorization_code') &&
      metadata.grant_types.includes('refresh_token') && metadata.dpop_bound_access_tokens === true
  }, 'Public OAuth metadata must match SERVICE_URL, provider callback, grants and DPoP.')
  await probe('web-cors-response', async () => {
    const response = await get(`${broker}/v1/sessions/exchange`, {
      method: 'OPTIONS', headers: {
        Origin: web, 'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type,authorization,x-m8-session-id',
      },
    })
    const methods = response.headers.get('access-control-allow-methods')?.split(',').map((value) => value.trim().toUpperCase()) ?? []
    const headers = response.headers.get('access-control-allow-headers')?.split(',').map((value) => value.trim().toLowerCase()) ?? []
    return response.ok && response.headers.get('access-control-allow-origin') === web && methods.includes('POST') &&
      ['content-type', 'authorization', 'x-m8-session-id'].every((header) => headers.includes(header))
  }, 'The deployed broker must accept the exact browser origin and exchange headers.')
  await probe('web-callback-route', async () => {
    const response = await get(`${web}/m8-auth`)
    return response.ok && Boolean(response.headers.get('content-type')?.includes('text/html'))
  }, 'The actual web host must serve HTML directly on /m8-auth; this does not prove the deployed JavaScript revision.')
  return checks
}
