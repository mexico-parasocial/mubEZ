import { GrowthBook, type FeatureDefinition } from '@growthbook/growthbook'
import env from '#start/env'

export enum Features {
  AuthDevTokenBootstrap = 'm8:auth:dev_token_bootstrap',
  DemoIdentityWalletEnable = 'm8:demo_identity_wallet:enable',
  SimulatedIneEnable = 'm8:simulated_ine:enable',
  LocalParaFallbackEnable = 'm8:local_para_fallback:enable',
  LocalTrustPolicyEnable = 'm8:local_trust_policy:enable',
  DevelopmentDeviceTrustEnable = 'm8:development_device_trust:enable',
  CommunityPdsAuthTokenFallbackEnable = 'm8:community:pds_auth_token_fallback:enable',
}

const nonProductionDefault = env.get('NODE_ENV') !== 'production'

const defaultFeatureValues: Record<Features, boolean> = {
  [Features.AuthDevTokenBootstrap]: nonProductionDefault,
  [Features.DemoIdentityWalletEnable]: nonProductionDefault,
  [Features.SimulatedIneEnable]: nonProductionDefault,
  [Features.LocalParaFallbackEnable]: nonProductionDefault,
  [Features.LocalTrustPolicyEnable]: nonProductionDefault,
  [Features.DevelopmentDeviceTrustEnable]: nonProductionDefault,
  [Features.CommunityPdsAuthTokenFallbackEnable]: nonProductionDefault,
}

function toGrowthBookFeatures(values: Record<Features, boolean>): Record<string, FeatureDefinition<boolean>> {
  return Object.fromEntries(
    Object.entries(values).map(([key, value]) => [key, { defaultValue: value }])
  )
}

function parseFeatureOverrides() {
  const featureOverrides = env.get('GROWTHBOOK_FEATURE_OVERRIDES')
  if (!featureOverrides) return new Map<string, unknown>()

  try {
    const parsed = JSON.parse(featureOverrides) as Record<string, unknown>
    return new Map(Object.entries(parsed))
  } catch {
    console.warn('[growthbook] Ignoring invalid GROWTHBOOK_FEATURE_OVERRIDES JSON')
    return new Map<string, unknown>()
  }
}

export const growthbook = new GrowthBook({
  apiHost: env.get('GROWTHBOOK_API_HOST'),
  clientKey: env.get('GROWTHBOOK_CLIENT_KEY'),
})

growthbook.setFeatures(toGrowthBookFeatures(defaultFeatureValues))
growthbook.setForcedFeatures(parseFeatureOverrides())

export const featureFlagsReady =
  env.get('GROWTHBOOK_API_HOST') && env.get('GROWTHBOOK_CLIENT_KEY')
    ? growthbook.init({ timeout: env.get('GROWTHBOOK_INIT_TIMEOUT_MS') }).catch((error) => {
        console.warn('[growthbook] Initialization failed or timed out', error)
        return { success: false, source: 'error' as const, error }
      })
    : Promise.resolve({ success: true, source: 'local' as const })

export function isFeatureEnabled(feature: Features): boolean {
  return growthbook.isOn(feature)
}

export function getFeatureValue<T>(feature: Features, fallback: T): T {
  return growthbook.getFeatureValue(feature, fallback) as T
}

export async function refreshFeatureFlags(timeout = env.get('GROWTHBOOK_INIT_TIMEOUT_MS')) {
  if (!env.get('GROWTHBOOK_API_HOST') || !env.get('GROWTHBOOK_CLIENT_KEY')) return
  await growthbook.refreshFeatures({ timeout })
}

/**
 * Demo/simulated/dev paths require BOTH:
 * 1. The GrowthBook feature flag is enabled.
 * 2. The environment is non-production OR an explicit break-glass env is set.
 *
 * This prevents a compromised or misconfigured GrowthBook flag from
 * accidentally exposing demo endpoints in production.
 */
export function assertDemoPathAllowed(feature: Features): boolean {
  if (!isFeatureEnabled(feature)) {
    return false
  }

  const inProduction = env.get('NODE_ENV') === 'production'
  const breakGlass = env.get('BREAK_GLASS_DEMO_PATHS') === 'enabled'

  if (inProduction && !breakGlass) {
    return false
  }

  return true
}

export function assertProductionFeatureSafety() {
  if (env.get('NODE_ENV') !== 'production' || env.get('BREAK_GLASS_DEMO_PATHS') === 'enabled') {
    return
  }

  const forced = parseFeatureOverrides()
  const forbidden = [
    Features.AuthDevTokenBootstrap,
    Features.DemoIdentityWalletEnable,
    Features.SimulatedIneEnable,
    Features.LocalParaFallbackEnable,
    Features.LocalTrustPolicyEnable,
    Features.DevelopmentDeviceTrustEnable,
    Features.CommunityPdsAuthTokenFallbackEnable,
  ].filter((feature) => forced.get(feature) === true)

  if (forbidden.length > 0) {
    throw new Error(
      `Production cannot force-enable demo or development feature flags without BREAK_GLASS_DEMO_PATHS=enabled: ${forbidden.join(', ')}`
    )
  }
}
