import { randomUUID } from 'node:crypto'
import env from '#start/env'
import { getDb } from '../db/connection.js'

export type DeviceTrustPlatform = 'ios' | 'android' | 'web'
export type DeviceTrustRiskTier = 'low' | 'medium' | 'high'
export type DeviceTrustStatus = 'unknown' | 'limited' | 'trusted'

export interface DeviceTrustSummary {
  status: DeviceTrustStatus
  platform: DeviceTrustPlatform | null
  riskTier: DeviceTrustRiskTier | null
  lastVerifiedAt: string | null
}

export function getDeviceTrustSummary(sessionId: string): DeviceTrustSummary {
  const db = getDb()
  const row = db.prepare(`
    SELECT platform, risk_tier, last_verified_at
    FROM trusted_devices
    WHERE session_id = ? AND attestation_status = 'verified'
    ORDER BY last_verified_at DESC, updated_at DESC
    LIMIT 1
  `).get(sessionId) as { platform: DeviceTrustPlatform; risk_tier: DeviceTrustRiskTier; last_verified_at: string | null } | undefined

  if (!row) {
    return { status: 'unknown', platform: null, riskTier: null, lastVerifiedAt: null }
  }

  return {
    status: row.risk_tier === 'high' ? 'trusted' : 'limited',
    platform: row.platform,
    riskTier: row.risk_tier,
    lastVerifiedAt: row.last_verified_at,
  }
}

export function assertTrustedDevice(sessionId: string, action: string): DeviceTrustSummary {
  const summary = getDeviceTrustSummary(sessionId)
  const allowed = summary.status === 'trusted'
  writeDeviceTrustEvent(sessionId, null, action, allowed ? 'allowed' : 'blocked', summary)
  if (!allowed) {
    throw appError('Trusted device required for this action', 403, 'TRUSTED_DEVICE_REQUIRED')
  }
  return summary
}

export function upsertDevelopmentTrustedDevice(sessionId: string, input: {
  platform: DeviceTrustPlatform
  deviceKeyId: string
  publicKey?: string
}): DeviceTrustSummary {
  if (env.get('NODE_ENV') === 'production') {
    throw appError('Development device trust override is disabled in production', 404, 'NOT_FOUND')
  }

  const db = getDb()
  const now = new Date().toISOString()
  const id = `trusted-device-${randomUUID()}`
  db.prepare(`
    INSERT INTO trusted_devices
      (id, session_id, platform, device_key_id, public_key, attestation_status, risk_tier, last_verified_at, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(session_id, device_key_id) DO UPDATE SET
      platform = excluded.platform,
      public_key = excluded.public_key,
      attestation_status = excluded.attestation_status,
      risk_tier = excluded.risk_tier,
      last_verified_at = excluded.last_verified_at,
      updated_at = excluded.updated_at
  `).run(
    id,
    sessionId,
    input.platform,
    input.deviceKeyId,
    input.publicKey ?? '',
    'verified',
    'high',
    now,
    now,
    now,
  )

  writeDeviceTrustEvent(sessionId, input.deviceKeyId, 'DevelopmentDeviceTrusted', 'trusted', {
    platform: input.platform,
    riskTier: 'high',
  })
  return getDeviceTrustSummary(sessionId)
}

function appError(message: string, statusCode: number, code: string) {
  return Object.assign(new Error(message), { statusCode, code })
}

function writeDeviceTrustEvent(
  sessionId: string,
  deviceId: string | null,
  action: string,
  result: string,
  detail: unknown,
) {
  const db = getDb()
  db.prepare(`
    INSERT INTO device_trust_events (session_id, device_id, action, result, detail_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(sessionId, deviceId, action, result, JSON.stringify(detail ?? {}), new Date().toISOString())
}
