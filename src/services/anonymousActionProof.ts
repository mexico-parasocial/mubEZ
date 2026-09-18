import {
  verifyIdentityAssertion,
  type SignedAssertion,
} from './identitySignature.js'
import {
  consumeChallenge,
  issueChallenge,
  type ChallengeBindings,
} from './assuranceReplayStore.js'

/*
 * Per-request proof of possession for anonymous-surface mutations (CD-10).
 *
 * This is the client->broker half of the broker's assurance roles: iM8 signs an
 * sr25519 PoP of its `anonymous` identity key over a server-issued single-use
 * challenge, under the `anon-action` purpose, and mubEZ verifies it here. It
 * combines the two shared pieces:
 *   - the CD-7 signature verifier (`verifyIdentityAssertion`) — proves the caller
 *     holds identity_pub, with purpose binding so a login/registration proof
 *     cannot be replayed as a mutation;
 *   - the CD-10 replay store (`assuranceReplayStore`) — proves the challenge is
 *     real, unspent, unexpired, and was issued for exactly this action.
 *
 * The signature covers the nonce (proving possession); the store binds the nonce
 * to the action (so a proof minted for one action cannot authorize another). No
 * session is involved at any step.
 */

/** The broker is both the audience of these proofs and the challenge issuer. */
export const BROKER_AUDIENCE = process.env.M8_BROKER_AUDIENCE?.trim() || 'mubez'
export const BROKER_ISSUER = process.env.M8_BROKER_ISSUER?.trim() || 'mubez'

/**
 * The action a proof authorizes, as an opaque descriptor the caller defines and
 * the client must match — e.g. 'create', 'update:<id>', 'link-post:<uri>'. It is
 * bound into the challenge at issue time and re-checked at consume time.
 */
export type AnonymousAction = string

/** Canonical, deterministic bindings a nonce is issued for and consumed against. */
function bindingsFor(identityPub: string, action: AnonymousAction): ChallengeBindings {
  return {
    subject: identityPub,
    binding: `anon-action/v1\naudience:${BROKER_AUDIENCE}\naction:${action}`,
  }
}

/**
 * Issue a single-use challenge for a specific identity key and action. The raw
 * nonce is returned once; the client signs it and calls back with the proof.
 */
export function issueAnonymousActionChallenge(
  identityPub: string,
  action: AnonymousAction,
  now: () => Date = () => new Date(),
): { nonce: string; expiresAt: number } {
  return issueChallenge(bindingsFor(identityPub, action), BROKER_ISSUER, now)
}

export type ActionProofResult =
  | { ok: true; identityPub: string }
  | { ok: false; reason: 'bad-proof' | 'bad-challenge' }

/**
 * Verify a mutation proof. The signature is checked before the challenge is
 * consumed, so a bad proof never burns the challenge; a verified proof consumes
 * it atomically (nonce + jti), so it cannot be replayed.
 *
 * `action` must be the action the caller is authorizing; it is re-derived into
 * the bindings and must match what the nonce was issued for.
 */
export function verifyAnonymousActionProof(
  input: { signed: SignedAssertion; jti: string; action: AnonymousAction },
  now: () => Date = () => new Date(),
): ActionProofResult {
  const signed = input.signed
  const challenge = signed?.assertion?.challenge
  const identityPub = signed?.assertion?.identityPub
  if (typeof challenge !== 'string' || typeof identityPub !== 'string') {
    return { ok: false, reason: 'bad-proof' }
  }
  if (typeof input.jti !== 'string' || input.jti.length === 0 || input.jti.length > 256) {
    return { ok: false, reason: 'bad-proof' }
  }

  const verified = verifyIdentityAssertion(signed, {
    purpose: 'anon-action',
    audience: BROKER_AUDIENCE,
    challenge,
    now: now(),
  })
  if (!verified) return { ok: false, reason: 'bad-proof' }

  const consumed = consumeChallenge(
    {
      nonce: challenge,
      jti: input.jti,
      bindings: bindingsFor(identityPub, input.action),
      issuer: BROKER_ISSUER,
    },
    now,
  )
  if (!consumed) return { ok: false, reason: 'bad-challenge' }

  return { ok: true, identityPub }
}
