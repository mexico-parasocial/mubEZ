/**
 * Scope policy maps PARA surfaces/personas to AT Protocol OAuth scopes.
 *
 * This module defines what OAuth capabilities each surface needs when
 * m8 authenticates on behalf of the user against their PDS.
 *
 * AT Protocol OAuth requires `atproto` to always be present.
 * Additional scopes are space-separated strings.
 *
 * ┌─────────────┬────────────────────────────────────────────────────────────┐
 * │ Surface     │ Scopes                                                     │
 * ├─────────────┼────────────────────────────────────────────────────────────┤
 * │ spark       │ atproto                                                    │
 * │             │ Base identity access. Anonymous mode. No PDS writes.       │
 * ├─────────────┼────────────────────────────────────────────────────────────┤
 * │ public      │ atproto + rpc:com.atproto.repo.applyWrites                │
 * │ (orbit)     │ Base identity. Can publish posts and read profile.         │
 * │             │ (Future: rpc:app.bsky.feed.* for timeline interactions)    │
 * ├─────────────┼────────────────────────────────────────────────────────────┤
 * │ civic       │ atproto                                                    │
 * │ (signal)    │ Base identity. Civic verification. No social writes.       │
 * │             │ (Future: rpc:com.atproto.repo.applyWrites for votes)       │
 * └─────────────┴────────────────────────────────────────────────────────────┘
 *
 * Note: `transition:generic` was removed — PARA is OAuth-native.
 */

import type { ProofBrokerSurfaceId } from '../types/index.js'

export type OAuthScopeSet = 'atproto' | 'atproto transition:generic'

const SCOPE_BASE = 'atproto' as const

/**
 * Map each surface to its required OAuth scope string.
 * All surfaces start with the base `atproto` scope.
 * Extended scopes are added as features are built (cross-posting,
 * profile sync, civic writes, etc.).
 */
export const SURFACE_SCOPES: Record<ProofBrokerSurfaceId, string> = {
  public: `${SCOPE_BASE} rpc:com.atproto.repo.applyWrites rpc:app.bsky.actor.getProfile`,
  civic: SCOPE_BASE,
  dating: SCOPE_BASE,
}

/**
 * Default scope when no surface is specified.
 * Used for the initial anonymous login (Spark persona).
 */
export const DEFAULT_OAUTH_SCOPE = SCOPE_BASE

/**
 * All scopes that m8 may ever request, for client_metadata registration.
 * This is the union of all surface scopes — the PDS sees this as the
 * maximum set of permissions m8 might need, but each login only requests
 * a subset via `client.authorize(scope)`.
 */
export const MAX_OAUTH_SCOPE = SCOPE_BASE

/**
 * Resolve the OAuth scope string for a given surface.
 */
export function scopeForSurface(surface?: ProofBrokerSurfaceId | string): string {
  if (!surface) return DEFAULT_OAUTH_SCOPE
  return SURFACE_SCOPES[surface as ProofBrokerSurfaceId] ?? DEFAULT_OAUTH_SCOPE
}

/**
 * Check whether a requested surface is valid.
 */
export function isValidSurface(surface: string): surface is ProofBrokerSurfaceId {
  return surface === 'public' || surface === 'civic' || surface === 'dating'
}
