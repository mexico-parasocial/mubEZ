import { z } from 'zod'
import type { HttpContext } from '@adonisjs/core/http'
import { getDb } from '../../src/db/connection.js'
import { getSessionId } from '#support/http'

const chatKeyBackupSchema = z.object({
  version: z.number().int().positive(),
  deviceId: z.string().min(1).max(256),
  ciphertext: z.string().min(1),
  encryptionMetadata: z.record(z.unknown()).default({}),
}).strict()

export default class ChatKeyBackupController {
  async createChatKeyBackup(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const parsed = chatKeyBackupSchema.safeParse(ctx.request.body())
    if (!parsed.success) {
      return ctx.response.status(400).send({
        error: 'Invalid encrypted chat key backup payload',
        issues: parsed.error.issues,
      })
    }

    const body = parsed.data
    const db = getDb()
    const now = new Date().toISOString()

    db.prepare(`
      INSERT INTO chat_key_backups
        (session_id, version, device_id, ciphertext, encryption_metadata_json, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(session_id) DO UPDATE SET
        version = excluded.version,
        device_id = excluded.device_id,
        ciphertext = excluded.ciphertext,
        encryption_metadata_json = excluded.encryption_metadata_json,
        updated_at = excluded.updated_at
    `).run(sessionId, body.version, body.deviceId, body.ciphertext, JSON.stringify(body.encryptionMetadata), now, now)

    db.prepare(`
      INSERT INTO ledger (session_id, action, target_type, target_id, detail_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(sessionId, 'ChatKeyBackupUpserted', 'chat_key_backup', sessionId, JSON.stringify({ version: body.version, deviceId: body.deviceId }), now)

    return ctx.response.send({ ok: true, updatedAt: now })
  }

  async getChatKeyBackup(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)

    const db = getDb()
    const row = db.prepare(`
      SELECT version, device_id, ciphertext, encryption_metadata_json, created_at, updated_at
      FROM chat_key_backups
      WHERE session_id = ?
    `).get(sessionId) as {
      version: number
      device_id: string
      ciphertext: string
      encryption_metadata_json: string
      created_at: string
      updated_at: string
    } | undefined

    if (!row) {
      return ctx.response.status(404).send({ error: 'Chat key backup not found' })
    }

    return ctx.response.send({
      version: row.version,
      deviceId: row.device_id,
      ciphertext: row.ciphertext,
      encryptionMetadata: JSON.parse(row.encryption_metadata_json),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    })
  }

  async deleteChatKeyBackup(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)

    const db = getDb()
    const now = new Date().toISOString()
    const result = db.prepare('DELETE FROM chat_key_backups WHERE session_id = ?').run(sessionId)

    db.prepare(`
      INSERT INTO ledger (session_id, action, target_type, target_id, detail_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(sessionId, 'ChatKeyBackupDeleted', 'chat_key_backup', sessionId, JSON.stringify({ deleted: result.changes > 0 }), now)

    return ctx.response.send({ deleted: result.changes > 0, deletedAt: now })
  }
}
