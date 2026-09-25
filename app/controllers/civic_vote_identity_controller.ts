import { z } from 'zod'
import { timingSafeEqual } from 'node:crypto'
import env from '#start/env'
import type { HttpContext } from '@adonisjs/core/http'
import { getSessionId, validateBody } from '#support/http'
import {
  issueCivicVoteProof,
  verifyCabildeoVoteProof,
} from '../../src/services/civicVoteIdentityService.js'
import {
  issueCivicDelegationProof,
  verifyCivicDelegationProof,
} from '../../src/services/civicDelegationService.js'

const subjectTypeSchema = z.enum([
  'cabildeo',
  'policy',
  'matter',
  'governance',
  'raq_axis',
  'raq_proposal',
  'community_proposal',
  'community_deliberation',
  'open_question_reply',
])

const proofSchema = z
  .object({
    subjectUri: z.string().min(1).max(1024),
    subjectType: subjectTypeSchema,
    selectedOption: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
  })
  .strict()

const verificationSchema = z.object({
  actorDid: z.string().startsWith('did:').max(512),
  subjectUri: z.string().startsWith('at://').max(1024),
  selectedOption: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  voteNullifier: z.string().regex(/^[a-f0-9]{64}$/),
  eligibilityProofRef: z.string().regex(/^m8:cabildeo:v1:[A-Za-z0-9_-]{43}$/),
}).strict()

const activeDelegationSchema = z.object({
  mode: z.literal('active'),
  delegateTo: z.string().startsWith('did:').max(512),
  cabildeo: z.string().startsWith('at://').max(1024),
})
const passiveDelegationSchema = z.object({
  mode: z.literal('passive'),
  delegateTo: z.string().startsWith('did:').max(512),
  party: z.string().min(1).max(100),
  community: z.string().min(1).max(100),
  scopeFlairs: z.array(z.string().min(1).max(100)).min(1).max(10),
})
const delegationSchema = z.discriminatedUnion('mode', [
  activeDelegationSchema,
  passiveDelegationSchema,
])
const delegationVerificationSchema = z.object({
  actorDid: z.string().startsWith('did:').max(512),
  eligibilityProofRef: z.string().regex(/^m8:delegation:v1:[0-9a-f-]{36}:[A-Za-z0-9_-]{43}$/),
  subjectUri: z.string().startsWith('at://').max(1024).optional(),
}).and(delegationSchema)

export default class CivicVoteIdentityController {
  async issueProof(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, proofSchema)
    if (!body) return
    return ctx.response.send({ proof: issueCivicVoteProof(sessionId, body) })
  }

  async verifyProof(ctx: HttpContext) {
    const body = validateBody(ctx, verificationSchema)
    if (!body) return
    if (!verifyCabildeoVoteProof(body)) {
      return ctx.response.status(422).send({ code: 'INVALID_VOTE_PROOF' })
    }
    return ctx.response.status(204).send(null)
  }

  async issueDelegationProof(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, delegationSchema)
    if (!body) return
    return ctx.response.send({ proof: issueCivicDelegationProof(sessionId, body) })
  }

  async verifyDelegationProof(ctx: HttpContext) {
    const body = validateBody(ctx, delegationVerificationSchema)
    if (!body) return
    if (body.subjectUri) {
      const secret = env.get('CIVIC_DELEGATION_RESOLVER_SECRET')
      const supplied = ctx.request.header('x-m8-resolver-secret') ?? ''
      if (!secret || supplied.length !== secret.length ||
          !timingSafeEqual(Buffer.from(supplied), Buffer.from(secret))) {
        return ctx.response.status(403).send({ code: 'RESOLVER_FORBIDDEN' })
      }
    }
    const result = verifyCivicDelegationProof(body)
    if (!result) return ctx.response.status(422).send({ code: 'INVALID_DELEGATION_PROOF' })
    return body.subjectUri
      ? ctx.response.send(result)
      : ctx.response.status(204).send(null)
  }

}
