import { createHash, randomBytes } from 'node:crypto'
import env from '#start/env'

export type AbuseEventType =
  | 'rate_limit_exceeded'
  | 'auth_failure'
  | 'validation_failure'
  | 'zkp_verification_failure'
  | 'suspicious_request'
  | 'alert_threshold_exceeded'

export type AbuseEvent = {
  type: AbuseEventType
  /** Privacy-preserving hash of the client IP (salted). */
  ipHash: string
  /** Request path (not query string, to avoid logging PII). */
  path: string
  method: string
  /** Privacy-preserving hash of the user agent. */
  userAgentHash: string
  /** Request ID from Adonis context. */
  requestId: string
  /** Session ID or null for unauthenticated requests. */
  sessionId: string | null
  /** Additional detail (never include PII). */
  detail?: string
  timestamp: string
}

/**
 * Privacy policy for abuse monitoring:
 * - We never store raw IPs or raw user agents.
 * - We store one-way salted hashes (SHA-256) using a runtime salt.
 * - The salt rotates every 24 hours and is never persisted.
 * - Retention: local buffer keeps last 1000 events; external logs should
 *   be rotated per org policy (suggested: 30 days hot, 90 days cold).
 * - Events are structured JSON lines suitable for ingestion by external
 *   SIEMs (e.g., Datadog, Splunk, CloudWatch Logs).
 */

let dailySalt = randomBytes(32).toString('hex')
const SALT_ROTATION_MS = 24 * 60 * 60 * 1000
setInterval(() => {
  dailySalt = randomBytes(32).toString('hex')
}, SALT_ROTATION_MS).unref()

function hashPrivacyField(value: string): string {
  return createHash('sha256').update(value + dailySalt).digest('hex').slice(0, 16)
}

const recentEvents: AbuseEvent[] = []
const MAX_BUFFER_SIZE = 1000

/** Per-type sliding-window counters for threshold alerting. */
const windowCounters = new Map<string, number[]>()

function pushEvent(event: AbuseEvent) {
  recentEvents.push(event)
  if (recentEvents.length > MAX_BUFFER_SIZE) {
    recentEvents.shift()
  }
}

function getWindowKey(type: AbuseEventType, ipHash: string): string {
  return `${type}:${ipHash}`
}

function incrementWindowCounter(key: string): number {
  const now = Date.now()
  const windowMs = env.get('RATE_LIMIT_WINDOW_MS')
  let entries = windowCounters.get(key) ?? []
  entries = entries.filter((t) => now - t < windowMs)
  entries.push(now)
  windowCounters.set(key, entries)
  return entries.length
}

function checkThresholdAlert(type: AbuseEventType, ipHash: string, count: number) {
  // Alert thresholds are 3x the rate limit for the same window
  const alertThreshold = env.get('RATE_LIMIT_MAX') * 3
  if (count >= alertThreshold) {
    const alertEvent: AbuseEvent = {
      type: 'alert_threshold_exceeded',
      ipHash,
      path: 'system',
      method: 'ALERT',
      userAgentHash: 'system',
      requestId: 'system',
      sessionId: null,
      detail: `type=${type} count=${count} threshold=${alertThreshold} window=${env.get('RATE_LIMIT_WINDOW_MS')}ms`,
      timestamp: new Date().toISOString(),
    }
    pushEvent(alertEvent)
    logStructured(alertEvent)
  }
}

function logStructured(event: AbuseEvent) {
  if (env.get('NODE_ENV') === 'test') return
  // Structured JSON line for external ingestion.
  // Format: {"service":"muvis","level":"warn","event":{...}}
  const structured = {
    service: 'muvis',
    level: 'warn',
    event,
  }
  // Use console.warn so pino (Adonis logger) picks it up.
  console.warn(JSON.stringify(structured))
}

export function recordAbuse(params: {
  type: AbuseEventType
  ip: string
  path: string
  method: string
  userAgent: string
  requestId: string
  sessionId?: string | null
  detail?: string
}) {
  const ipHash = hashPrivacyField(params.ip)
  const userAgentHash = hashPrivacyField(params.userAgent)

  const event: AbuseEvent = {
    type: params.type,
    ipHash,
    path: params.path,
    method: params.method,
    userAgentHash,
    requestId: params.requestId,
    sessionId: params.sessionId ?? null,
    detail: params.detail,
    timestamp: new Date().toISOString(),
  }

  pushEvent(event)
  logStructured(event)

  const windowKey = getWindowKey(params.type, ipHash)
  const count = incrementWindowCounter(windowKey)
  checkThresholdAlert(params.type, ipHash, count)
}

export function getRecentAbuseEvents(
  options: {
    ipHash?: string
    type?: AbuseEventType
    since?: string
    limit?: number
  } = {}
): AbuseEvent[] {
  let filtered = recentEvents

  if (options.ipHash) {
    filtered = filtered.filter((e) => e.ipHash === options.ipHash)
  }
  if (options.type) {
    filtered = filtered.filter((e) => e.type === options.type)
  }
  if (options.since) {
    const sinceMs = new Date(options.since).getTime()
    filtered = filtered.filter((e) => new Date(e.timestamp).getTime() >= sinceMs)
  }

  const limit = options.limit ?? 100
  return filtered.slice(-limit)
}

export function countAbuseEvents(ipHash: string, type: AbuseEventType, windowMs: number): number {
  const cutoff = Date.now() - windowMs
  return recentEvents.filter(
    (e) => e.ipHash === ipHash && e.type === type && new Date(e.timestamp).getTime() >= cutoff
  ).length
}
