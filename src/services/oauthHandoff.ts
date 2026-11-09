/** Resolve explicit native/web handoffs before creating an OAuth attempt. */
export function resolveOAuthHandoff(
  platform: 'web' | 'mobile' | undefined,
  requested: string | undefined,
  enabled: boolean,
  allowlist: string,
): string | null {
  if (!platform) return null
  if (!enabled) throw new Error('OAUTH_HANDOFF_UNAVAILABLE')
  const allowed = allowlist
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean)
  const target = requested ?? (platform === 'mobile' ? allowed[0] : undefined)
  if (!target || !allowed.includes(target)) throw new Error('OAUTH_RETURN_TO_INVALID')
  const url = new URL(target)
  if (url.username || url.password || url.search || url.hash) throw new Error('OAUTH_RETURN_TO_INVALID')
  if (
    platform === 'web' &&
    url.protocol !== 'https:' &&
    !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))
  )
    throw new Error('OAUTH_RETURN_TO_INVALID')
  return target
}

/** No bearer token, session id or provider error detail belongs in a redirect. */
export function oauthHandoffUrl(
  returnTo: string,
  attemptId: string,
  outcome: { code: string } | { error: string },
): string {
  const url = new URL(returnTo)
  url.searchParams.set('attempt_id', attemptId)
  if ('code' in outcome) url.searchParams.set('exchange_code', outcome.code)
  else url.searchParams.set('error', outcome.error)
  return url.toString()
}
