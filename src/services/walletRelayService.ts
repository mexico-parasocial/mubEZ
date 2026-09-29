import { randomUUID } from 'node:crypto'
import { getDb } from '../db/connection.js'
import { ensureIssuanceChallenge } from './issuanceChallenge.js'
import { parseHolderPublicKey, verifyHolderKeyProof } from './identityWallet.js'
import type {
  M8IdentityCredential,
  M8IdentityRequest,
  M8IdentityVerificationResult,
} from '../types/index.js'

/*
 * iM8 wallet relay (CD-14), on the pattern of the Matrix sign-request relay.
 *
 * PARA never holds a holder key or a credential. When PARA runs an INE
 * issuance it asks, through the shared M8 session, for a holder binding; the
 * iM8 wallet generates a key on the device, and posts back only the public key
 * and a proof of possession over the issuance challenge snapshotted here. PARA
 * then issues against that binding by id, and the issued credentials wait in
 * this row until the wallet collects them — once. For presentations, the
 * identity request itself is the mailbox: PARA creates it, the wallet lists
 * it, signs on the device and submits to /identity/verify, and PARA reads the
 * minimal result back once.
 *
 * The broker stores public keys, proofs and (briefly) credentials it issued
 * itself. Nothing here can sign as the holder.
 */

/** Long enough for an INE capture and a ZK proof between request and issuance. */
export const WALLET_BINDING_TTL_SEC = 15 * 60
/** Cap on outstanding binding requests per session, to bound abuse. */
export const MAX_OPEN_BINDING_REQUESTS_PER_SESSION = 3

export type WalletBindingStatus = 'pending' | 'bound' | 'issued' | 'collected' | 'declined'

export type WalletBindingRequestView = {
  id: string
  issuanceChallenge: string
  status: WalletBindingStatus
  createdAt: string
  expiresAt: string
}

export type WalletCredentialDelivery = {
  proofArtifactId: string
  credential: M8IdentityCredential
  basicCredential: M8IdentityCredential
}

function pruneExpired() {
  getDb()
    .prepare("DELETE FROM wallet_binding_requests WHERE expires_at <= datetime('now')")
    .run()
}

const toView = (row: Record<string, unknown>): WalletBindingRequestView => ({
  id: row.id as string,
  issuanceChallenge: row.issuance_challenge as string,
  status: row.status as WalletBindingStatus,
  createdAt: row.created_at as string,
  expiresAt: row.expires_at as string,
})

function getRow(sessionId: string, id: string) {
  pruneExpired()
  return getDb()
    .prepare('SELECT * FROM wallet_binding_requests WHERE id = ? AND session_id = ?')
    .get(id, sessionId) as Record<string, unknown> | undefined
}

/** PARA: open a binding request against the session's current issuance challenge. */
export function createWalletBindingRequest(sessionId: string): WalletBindingRequestView {
  pruneExpired()
  const open = getDb()
    .prepare(
      "SELECT COUNT(*) AS count FROM wallet_binding_requests WHERE session_id = ? AND status IN ('pending', 'bound')"
    )
    .get(sessionId) as { count: number }
  if (open.count >= MAX_OPEN_BINDING_REQUESTS_PER_SESSION) {
    throw new Error('Too many open wallet binding requests for this session')
  }

  const id = `wallet-binding-${randomUUID()}`
  getDb()
    .prepare(
      `INSERT INTO wallet_binding_requests (id, session_id, issuance_challenge, expires_at)
       VALUES (?, ?, ?, datetime('now', '+${WALLET_BINDING_TTL_SEC} seconds'))`
    )
    .run(id, sessionId, ensureIssuanceChallenge(sessionId))
  return toView(getRow(sessionId, id)!)
}

/** Wallet: what is waiting — requests to bind, and issued credentials to collect. */
export function listWalletBindingRequests(sessionId: string): WalletBindingRequestView[] {
  pruneExpired()
  const rows = getDb()
    .prepare(
      "SELECT * FROM wallet_binding_requests WHERE session_id = ? AND status IN ('pending', 'issued') ORDER BY created_at DESC"
    )
    .all(sessionId) as Array<Record<string, unknown>>
  return rows.map(toView)
}

/** PARA's poll. Carries no key material: PARA issues by request id. */
export function getWalletBindingRequest(sessionId: string, id: string): WalletBindingRequestView | undefined {
  const row = getRow(sessionId, id)
  return row ? toView(row) : undefined
}

export type BindingResult =
  | { ok: true }
  | { ok: false; reason: 'not-found' | 'not-pending' | 'invalid-proof' }

/**
 * Wallet: bind a device-generated holder key. Accepted only when the proof
 * signs exactly this request's snapshotted issuance challenge.
 */
export function fulfillWalletBindingRequest(
  sessionId: string,
  id: string,
  input: { holderPublicKey: string; holderKeyProof: string },
): BindingResult {
  const row = getRow(sessionId, id)
  if (!row) return { ok: false, reason: 'not-found' }
  if (row.status !== 'pending') return { ok: false, reason: 'not-pending' }
  if (!verifyHolderKeyProof(input.holderPublicKey, row.issuance_challenge as string, input.holderKeyProof)) {
    return { ok: false, reason: 'invalid-proof' }
  }
  const updated = getDb()
    .prepare(
      "UPDATE wallet_binding_requests SET status = 'bound', holder_public_key = ? WHERE id = ? AND status = 'pending'"
    )
    .run(input.holderPublicKey.trim(), id)
  return updated.changes === 1 ? { ok: true } : { ok: false, reason: 'not-pending' }
}

export function declineWalletBindingRequest(sessionId: string, id: string): BindingResult {
  const row = getRow(sessionId, id)
  if (!row) return { ok: false, reason: 'not-found' }
  const updated = getDb()
    .prepare(
      "UPDATE wallet_binding_requests SET status = 'declined' WHERE id = ? AND status IN ('pending', 'bound')"
    )
    .run(id)
  return updated.changes === 1 ? { ok: true } : { ok: false, reason: 'not-pending' }
}

/**
 * Issuance: the holder key a bound request carries, if it was bound against
 * the challenge being presented. The possession proof was verified at bind.
 */
export function boundHolderKeyForIssuance(
  sessionId: string,
  id: string,
  issuanceChallenge: string,
): string | null {
  const row = getRow(sessionId, id)
  if (!row || row.status !== 'bound') return null
  if (row.issuance_challenge !== issuanceChallenge) return null
  const key = row.holder_public_key as string | null
  return key && parseHolderPublicKey(key) ? key : null
}

/** Issuance: hand the credentials to the wallet's mailbox. */
export function depositIssuedCredentials(sessionId: string, id: string, delivery: WalletCredentialDelivery) {
  getDb()
    .prepare(
      `UPDATE wallet_binding_requests
       SET status = 'issued', credentials_json = ?,
           expires_at = datetime('now', '+${WALLET_BINDING_TTL_SEC} seconds')
       WHERE id = ? AND session_id = ? AND status = 'bound'`
    )
    .run(JSON.stringify(delivery), id, sessionId)
}

/** Wallet: take the issued credentials. Returned once, then erased here. */
export function collectIssuedCredentials(sessionId: string, id: string): WalletCredentialDelivery | null {
  const db = getDb()
  return db.transaction(() => {
    const row = getRow(sessionId, id)
    if (!row || row.status !== 'issued' || !row.credentials_json) return null
    db.prepare(
      "UPDATE wallet_binding_requests SET status = 'collected', credentials_json = NULL WHERE id = ?"
    ).run(id)
    return JSON.parse(row.credentials_json as string) as WalletCredentialDelivery
  })()
}

// ─── Presentation mailbox (identity_requests) ──────────────────────────────

export function rowToIdentityRequest(row: Record<string, unknown>): M8IdentityRequest {
  return {
    id: row.id as string,
    sessionId: row.session_id as string,
    nonce: row.nonce as string,
    audienceAppId: row.audience_app_id as string,
    audienceAppName: row.audience_app_name as string,
    purpose: row.purpose as string,
    merchantIdentifier: row.merchant_identifier as string,
    requestedElements: JSON.parse(row.requested_elements_json as string),
    status: row.status as M8IdentityRequest['status'],
    createdAt: row.created_at as string,
    expiresAt: row.expires_at as string,
    usedAt: row.used_at as string | null,
  }
}

/** Wallet: live requests waiting for a presentation on this session. */
export function listActiveIdentityRequests(sessionId: string): M8IdentityRequest[] {
  const rows = getDb()
    .prepare("SELECT * FROM identity_requests WHERE session_id = ? AND status = 'active' ORDER BY created_at DESC")
    .all(sessionId) as Array<Record<string, unknown>>
  const now = Date.now()
  return rows.map(rowToIdentityRequest).filter((request) => Date.parse(request.expiresAt) > now)
}

export function declineIdentityRequest(sessionId: string, id: string): boolean {
  const updated = getDb()
    .prepare("UPDATE identity_requests SET status = 'declined' WHERE id = ? AND session_id = ? AND status = 'active'")
    .run(id, sessionId)
  return updated.changes === 1
}

/** What a requester may read back: no subject, no credential, no holder key. */
export type StoredVerificationResult = Pick<
  M8IdentityVerificationResult,
  'valid' | 'disclosedClaims' | 'disclosure' | 'revealedClaimIds' | 'issuerDid' | 'checkedAt'
>

export function minimalVerificationResult(result: M8IdentityVerificationResult): StoredVerificationResult {
  return {
    valid: result.valid,
    disclosedClaims: result.disclosedClaims,
    disclosure: result.disclosure,
    revealedClaimIds: result.revealedClaimIds,
    issuerDid: result.issuerDid,
    checkedAt: result.checkedAt,
  }
}

/**
 * Requester's poll. The result is returned on the first read after the
 * wallet presented and then erased; later reads say it was delivered.
 */
export function readIdentityRequestOutcome(sessionId: string, id: string):
  | { id: string; status: M8IdentityRequest['status']; expiresAt: string; result?: StoredVerificationResult; resultDelivered: boolean }
  | undefined {
  const db = getDb()
  return db.transaction(() => {
    const row = db
      .prepare('SELECT * FROM identity_requests WHERE id = ? AND session_id = ?')
      .get(id, sessionId) as Record<string, unknown> | undefined
    if (!row) return undefined
    const status = row.status as M8IdentityRequest['status']
    const base = { id, status, expiresAt: row.expires_at as string }
    if (status === 'used' && row.result_json) {
      db.prepare('UPDATE identity_requests SET result_json = NULL WHERE id = ?').run(id)
      return { ...base, result: JSON.parse(row.result_json as string) as StoredVerificationResult, resultDelivered: true }
    }
    return { ...base, resultDelivered: status === 'used' }
  })()
}
