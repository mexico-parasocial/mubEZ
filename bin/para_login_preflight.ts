import env from '#start/env'
import { featureFlagsReady, Features, isFeatureEnabled } from '../src/services/features.js'
import { checkLoginConfiguration, checkLoginEndpoints } from '../src/services/paraLoginPreflight.js'

const args = process.argv.slice(2)
const webIndex = args.indexOf('--web-origin')
const webOrigin = webIndex >= 0 ? args[webIndex + 1] : undefined
const validArgs = args.filter((_, index) => index !== webIndex && index !== webIndex + 1)
if (!webOrigin || webOrigin.startsWith('--') || validArgs.some((arg) => !['--local', '--config-only'].includes(arg))) {
  console.error('Usage: tsx bin/para_login_preflight.ts --web-origin https://PARA_HOST [--local] [--config-only]')
  process.exit(2)
}

const loaded = await featureFlagsReady
const config = {
  serviceUrl: env.get('SERVICE_URL'), webOrigin,
  allowlist: env.get('OAUTH_RETURN_TO_ALLOWLIST'), corsOrigin: env.get('CORS_ORIGIN'),
  databasePath: env.get('DATABASE_PATH'),
  handoffEnabled: isFeatureEnabled(Features.OAuthMobileHandoff),
  bootstrapEnabled: isFeatureEnabled(Features.AuthDevTokenBootstrap),
  featureFlagsLoaded: loaded.success, local: args.includes('--local'),
}
const configOnly = args.includes('--config-only')
const checks = checkLoginConfiguration(config)
if (!configOnly) checks.push(...await checkLoginEndpoints(config))
const passed = checks.every((check) => check.passed)
console.log(JSON.stringify({
  status: passed ? 'passed' : 'blocked',
  scope: configOnly ? 'configuration-only' : 'configuration-and-public-endpoints',
  target: config.local ? 'local' : 'deployment',
  checks,
  remaining: 'This invocation checks its own environment/database, not the running server flags or code revision. Record deployed revisions, then perform real provider and supported-client acceptance. No credentials were issued.',
}, null, 2))
process.exit(passed ? 0 : 1)
