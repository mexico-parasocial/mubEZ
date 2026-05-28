/**
 * AT Protocol XRPC client backed by the user's OAuth session.
 *
 * Uses the stored OAuth session (from @atproto/oauth-client-node) to make
 * DPoP-authenticated requests to the user's PDS. This allows m8 to act on
 * behalf of the user for cross-posting, profile sync, and other PDS ops.
 */

import { restoreOAuthSession } from './atprotoAuth.js'
import { resolvePdsEndpoint } from './didResolver.js'

export class AtprotoAgentError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly status = 500,
  ) {
    super(message)
  }
}

/**
 * Build a fully-qualified XRPC URL for the user's PDS.
 */
export async function xrpcUrl(did: string, method: string): Promise<string> {
  const pds = await resolvePdsEndpoint(did)
  if (!pds) {
    throw new AtprotoAgentError('Could not resolve PDS endpoint for user', 'PDS_NOT_FOUND', 503)
  }
  const base = pds.endsWith('/') ? pds.slice(0, -1) : pds
  return `${base}/xrpc/${method}`
}

/**
 * Make an authenticated XRPC request using the user's OAuth session.
 *
 * @param did      The user's DID
 * @param method   XRPC method name (e.g. 'com.atproto.repo.createRecord')
 * @param init     Fetch init options (method, body, etc.)
 */
export async function xrpcRequest(
  did: string,
  method: string,
  init: RequestInit = {},
): Promise<unknown> {
  const session = await restoreOAuthSession(did)
  if (!session) {
    throw new AtprotoAgentError(
      'OAuth session not found or expired. Please re-authenticate.',
      'OAUTH_SESSION_MISSING',
      401,
    )
  }

  const url = await xrpcUrl(did, method)

  // The OAuthSession fetchHandler expects a pathname, but we need a full URL.
  // We use the session's underlying server agent to make authenticated requests.
  // Actually, fetchHandler takes (pathname, init) and prepends the PDS URL.
  // Let's extract the pathname from the URL.
  const urlObj = new URL(url)
  const pathname = urlObj.pathname + urlObj.search

  const response = await (session as { fetchHandler(path: string, init?: RequestInit): Promise<Response> }).fetchHandler(
    pathname,
    {
      ...init,
      headers: {
        'Content-Type': 'application/json',
        ...init.headers,
      },
    },
  )

  if (!response.ok) {
    const body = await response.text()
    let parsed: Record<string, unknown> | null = null
    try {
      parsed = JSON.parse(body) as Record<string, unknown>
    } catch {
      // ignore parse error
    }
    const message = parsed?.message ?? body ?? `XRPC request failed: ${response.status}`
    throw new AtprotoAgentError(
      message as string,
      (parsed?.error as string) || 'XRPC_ERROR',
      response.status,
    )
  }

  // Some XRPC methods return 200 with no body (e.g. delete)
  const contentType = response.headers.get('content-type') ?? ''
  if (contentType.includes('application/json')) {
    return response.json()
  }
  return { success: true }
}

/**
 * Create a Bluesky post (app.bsky.feed.post) on the user's PDS.
 */
export async function createBlueskyPost(
  did: string,
  post: {
    text: string
    createdAt?: string
    reply?: {
      root: { uri: string; cid: string }
      parent: { uri: string; cid: string }
    }
    embed?: unknown
  },
): Promise<{ uri: string; cid: string }> {
  const record = {
    $type: 'app.bsky.feed.post',
    text: post.text,
    createdAt: post.createdAt ?? new Date().toISOString(),
    ...(post.reply ? { reply: post.reply } : {}),
    ...(post.embed ? { embed: post.embed } : {}),
  }

  const result = await xrpcRequest(did, 'com.atproto.repo.createRecord', {
    method: 'POST',
    body: JSON.stringify({
      repo: did,
      collection: 'app.bsky.feed.post',
      record,
    }),
  }) as { uri: string; cid: string }

  return result
}

/**
 * Get the user's Bluesky profile.
 */
export async function getBlueskyProfile(did: string): Promise<unknown> {
  return xrpcRequest(did, 'app.bsky.actor.getProfile', {
    method: 'GET',
    body: JSON.stringify({ actor: did }),
  })
}
