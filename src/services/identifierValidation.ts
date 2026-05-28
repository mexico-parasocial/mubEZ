/**
 * AT Protocol identifier validation and normalization.
 *
 * Handles three forms of input:
 * - Handle:     `user.bsky.social` or `@user.bsky.social`
 * - DID:        `did:plc:abc123` or `did:web:example.com`
 * - Service URL: `https://pds.example.com`
 */

const DID_RE = /^did:(?:plc|web):[a-zA-Z0-9._:%-]+$/
const HANDLE_RE = /^(?:@?[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])$/
const SERVICE_URL_RE = /^https:\/\/[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9](?::\d+)?(?:\/.*)?$/

export type IdentifierKind = 'handle' | 'did' | 'service' | 'invalid'

export interface IdentifierResult {
  kind: IdentifierKind
  raw: string
  normalized: string
  error?: string
}

export function classifyIdentifier(input: string): IdentifierResult {
  const trimmed = input.trim()

  if (!trimmed) {
    return { kind: 'invalid', raw: input, normalized: '', error: 'Identifier is required' }
  }

  // DID
  if (trimmed.startsWith('did:')) {
    if (DID_RE.test(trimmed)) {
      return { kind: 'did', raw: input, normalized: trimmed }
    }
    return { kind: 'invalid', raw: input, normalized: trimmed, error: 'Invalid DID format' }
  }

  // Service URL
  if (trimmed.startsWith('https://') || trimmed.startsWith('http://')) {
    if (SERVICE_URL_RE.test(trimmed)) {
      return { kind: 'service', raw: input, normalized: trimmed }
    }
    return {
      kind: 'invalid',
      raw: input,
      normalized: trimmed,
      error: 'Invalid service URL. Must be a valid HTTPS URL',
    }
  }

  // Handle (with optional @ prefix)
  const handleCandidate = trimmed.startsWith('@') ? trimmed.slice(1) : trimmed
  if (HANDLE_RE.test(handleCandidate)) {
    return { kind: 'handle', raw: input, normalized: handleCandidate }
  }

  // Bare username that might be a handle without TLD
  if (/^[a-zA-Z0-9]([a-zA-Z0-9_-]{0,30}[a-zA-Z0-9])?$/.test(handleCandidate)) {
    return {
      kind: 'handle',
      raw: input,
      normalized: handleCandidate,
      error: 'INCOMPLETE_HANDLE',
    }
  }

  return {
    kind: 'invalid',
    raw: input,
    normalized: trimmed,
    error: 'Invalid identifier. Enter a handle (user.bsky.social), DID (did:plc:…), or service URL (https://…)',
  }
}

/**
 * If the identifier is a bare username (no dots), append the domain suffix.
 * Returns the original identifier if no domain is configured or if it's
 * already a complete handle, DID, or URL.
 */
export function applyHandleDomain(identifier: string, domain?: string): string {
  if (!domain) return identifier

  const trimmed = identifier.trim()
  if (trimmed.startsWith('did:') || trimmed.startsWith('https://') || trimmed.startsWith('http://')) {
    return identifier
  }

  const handle = trimmed.startsWith('@') ? trimmed.slice(1) : trimmed
  if (handle.includes('.')) return identifier

  const suffix = domain.startsWith('.') ? domain : `.${domain}`
  return `${handle}${suffix}`
}
