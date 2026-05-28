import Database from 'better-sqlite3'
import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import env from '#start/env'

let dbInstance: Database.Database | null = null
let dbPath: string | null = null

export function getDb(): Database.Database {
  if (dbInstance && dbPath === env.get('DATABASE_PATH')) return dbInstance

  if (dbInstance) {
    dbInstance.close()
  }

  const databasePath = env.get('DATABASE_PATH')
  mkdirSync(dirname(databasePath), { recursive: true })

  dbPath = databasePath
  dbInstance = new Database(databasePath)
  dbInstance.pragma('journal_mode = WAL')
  dbInstance.pragma('foreign_keys = ON')

  return dbInstance
}

export function closeDb(): void {
  if (dbInstance) {
    dbInstance.close()
    dbInstance = null
    dbPath = null
  }
}

export async function resetDb(): Promise<void> {
  closeDb()
  try {
    const { unlinkSync } = await import('node:fs')
    unlinkSync(env.get('DATABASE_PATH'))
  } catch {
    // ignore
  }
}
