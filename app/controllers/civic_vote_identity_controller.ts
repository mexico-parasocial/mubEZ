import { z } from 'zod'
import type { HttpContext } from '@adonisjs/core/http'
import { getSessionId, validateBody } from '#support/http'
import {
  issueCivicVoteProof,
  verifyCabildeoVoteProof,
} from '../../src/services/civicVoteIdentityService.js'

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

}
