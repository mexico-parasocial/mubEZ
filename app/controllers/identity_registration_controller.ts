import { z } from 'zod'
import type { HttpContext } from '@adonisjs/core/http'
import { validateBody } from '#support/http'
import {
  issueRegistrationChallenge,
  registerIdentity,
} from '../../src/services/identityRegistrationService.js'
import { issueAnonymousActionChallenge } from '../../src/services/anonymousActionProof.js'

/*
 * Identity registration (CRYPTO_DECISIONS.md CD-9). These routes are public on
 * purpose: registration must not be tied to a session, so no auth middleware
 * runs and the controller never reads a session id. The proof of possession is
 * the authorization.
 */

const hex = (bytes: number) =>
  z
    .string()
    .regex(new RegExp(`^[0-9a-f]{${bytes * 2}}$`), `expected ${bytes}-byte hex`)

const actionChallengeSchema = z
  .object({
    identityPub: hex(32),
    action: z.string().min(1).max(256),
  })
  .strict()

const registerSchema = z
  .object({
    signed: z
      .object({
        assertion: z
          .object({
            type: z.literal('para.identity.pop.v1'),
            purpose: z.literal('mubez-registration'),
            audience: z.string().min(1).max(256),
            identityPub: hex(32),
            challenge: z.string().min(1).max(512),
            signedAt: z.string().min(1).max(64),
          })
          .strict(),
        signature: hex(64),
      })
      .strict(),
  })
  .strict()

export default class IdentityRegistrationController {
  /** Issue a fresh, single-use, session-unbound challenge to sign over. */
  async challenge(ctx: HttpContext) {
    return ctx.response.send({ challenge: issueRegistrationChallenge() })
  }

  /**
   * Issue a single-use challenge for an anonymous-surface mutation (CD-10),
   * bound to the identity key and the action. Public and session-unbound: the
   * proof of possession, not the session, is the authorization.
   */
  async actionChallenge(ctx: HttpContext) {
    const body = validateBody(ctx, actionChallengeSchema)
    if (!body) return
    const { nonce, expiresAt } = issueAnonymousActionChallenge(body.identityPub, body.action)
    return ctx.response.send({ challenge: nonce, expiresAt })
  }

  /** Register an identity public key from its proof of possession. */
  async register(ctx: HttpContext) {
    const body = validateBody(ctx, registerSchema)
    if (!body) return

    const result = registerIdentity(body.signed)
    if (!result.ok) {
      // A bad challenge and a bad proof are both authentication failures to the
      // caller; the distinction is for logs, not for a probing client.
      return ctx.response.status(401).send({ error: 'Registration rejected' })
    }
    return ctx.response.status(result.alreadyRegistered ? 200 : 201).send({
      registered: true,
      alreadyRegistered: result.alreadyRegistered,
    })
  }
}
