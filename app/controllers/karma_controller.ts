import { randomUUID } from 'node:crypto'
import { z } from 'zod'
import type { HttpContext } from '@adonisjs/core/http'
import { getDb } from '../../src/db/connection.js'
import { getAnonymousProfile } from '../../src/services/anonymousProfileService.js'
import { getSessionId, validateBody } from '#support/http'
import { getCommunity } from '../../src/services/communityService.js'

const earnSchema = z.object({
  actionType: z.string().min(1),
  communityId: z.string().optional(),
  points: z.number().int().optional(),
  detail: z.record(z.unknown()).optional(),
}).strict()

const revelationSchema = z.object({
  revealGlobal: z.boolean().optional(),
  revealCommunities: z.array(z.string()).optional(),
}).strict()

export default class KarmaController {
  async earn(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, earnSchema)
    if (!body) return

    const anon = getAnonymousProfile(sessionId)
    if (!anon) {
      return ctx.response.status(400).send({ error: 'Anonymous profile required' })
    }

    // If community-scoped karma, validate membership
    if (body.communityId) {
      const community = getCommunity(body.communityId)
      if (!community) {
        return ctx.response.status(404).send({ error: 'Community not found', code: 'COMMUNITY_NOT_FOUND' })
      }

      const sessionRow = getDb().prepare('SELECT did FROM sessions WHERE session_id = ?').get(sessionId) as
        | { did: string }
        | undefined
      const userDid = sessionRow?.did

      if (userDid) {
        const isMember = getDb()
          .prepare('SELECT 1 FROM community_memberships WHERE community_id = ? AND member_did = ? AND status = ?')
          .get(body.communityId, userDid, 'active') as { '1': number } | undefined

        if (!isMember) {
          return ctx.response.status(403).send({
            error: 'You must be an active member of this community to earn karma',
            code: 'NOT_COMMUNITY_MEMBER',
          })
        }
      }
    }

    const id = `karma-${randomUUID()}`
    getDb().prepare(`
      INSERT INTO karma (id, anonymous_profile_id, community_id, action_type, points, detail_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      anon.id,
      body.communityId ?? null,
      body.actionType,
      body.points ?? 1,
      JSON.stringify(body.detail ?? {}),
      new Date().toISOString(),
    )

    return ctx.response.send({ earned: true, id, points: body.points ?? 1 })
  }

  async me(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)

    const anon = getAnonymousProfile(sessionId)
    if (!anon) {
      return ctx.response.send({ global: 0, byCommunity: [], actions: [] })
    }

    const rows = getDb().prepare(`
      SELECT community_id, action_type, SUM(points) as total
      FROM karma
      WHERE anonymous_profile_id = ?
      GROUP BY community_id, action_type
    `).all(anon.id) as Array<{ community_id: string | null; action_type: string; total: number }>

    const byCommunity: Record<string, number> = {}
    let global = 0
    const actions: Record<string, number> = {}

    for (const row of rows) {
      global += row.total
      if (row.community_id) {
        byCommunity[row.community_id] = (byCommunity[row.community_id] ?? 0) + row.total
      }
      actions[row.action_type] = (actions[row.action_type] ?? 0) + row.total
    }

    return ctx.response.send({ global, byCommunity, actions, profileId: anon.id })
  }

  async show(ctx: HttpContext) {
    const { profileId } = ctx.params
    const db = getDb()

    const revelation = db.prepare(
      'SELECT reveal_global, reveal_communities_json FROM karma_revelation WHERE anonymous_profile_id = ?'
    ).get(profileId) as { reveal_global: number; reveal_communities_json: string } | undefined

    const rows = db.prepare(`
      SELECT community_id, action_type, SUM(points) as total
      FROM karma
      WHERE anonymous_profile_id = ?
      GROUP BY community_id, action_type
    `).all(profileId) as Array<{ community_id: string | null; action_type: string; total: number }>

    const revealGlobal = revelation?.reveal_global === 1
    const revealCommunities = new Set<string>(JSON.parse(revelation?.reveal_communities_json ?? '[]') as string[])

    let global = 0
    const byCommunity: Record<string, number> = {}
    const actions: Record<string, number> = {}

    for (const row of rows) {
      global += row.total
      if (row.community_id) {
        byCommunity[row.community_id] = (byCommunity[row.community_id] ?? 0) + row.total
      }
      actions[row.action_type] = (actions[row.action_type] ?? 0) + row.total
    }

    return ctx.response.send({
      profileId,
      global: revealGlobal ? global : null,
      byCommunity: Object.fromEntries(
        Object.entries(byCommunity).filter(([cid]) => revealCommunities.has(cid))
      ),
      actions: revealGlobal ? actions : {},
      revealed: { global: revealGlobal, communities: Array.from(revealCommunities) },
    })
  }

  async updateRevelation(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, revelationSchema)
    if (!body) return

    const anon = getAnonymousProfile(sessionId)
    if (!anon) {
      return ctx.response.status(400).send({ error: 'Anonymous profile required' })
    }

    const db = getDb()
    const existing = db.prepare('SELECT 1 FROM karma_revelation WHERE anonymous_profile_id = ?').get(anon.id)
    if (existing) {
      db.prepare(`
        UPDATE karma_revelation
        SET reveal_global = ?, reveal_communities_json = ?, updated_at = ?
        WHERE anonymous_profile_id = ?
      `).run(
        body.revealGlobal ? 1 : 0,
        JSON.stringify(body.revealCommunities ?? []),
        new Date().toISOString(),
        anon.id,
      )
    } else {
      db.prepare(`
        INSERT INTO karma_revelation (anonymous_profile_id, reveal_global, reveal_communities_json, updated_at)
        VALUES (?, ?, ?, ?)
      `).run(
        anon.id,
        body.revealGlobal ? 1 : 0,
        JSON.stringify(body.revealCommunities ?? []),
        new Date().toISOString(),
      )
    }

    return ctx.response.send({ updated: true })
  }
}
