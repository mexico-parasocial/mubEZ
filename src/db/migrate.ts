import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { getDb } from './connection.js'

export function runMigrations() {
  const db = getDb()

  db.exec(`
    CREATE TABLE IF NOT EXISTS migrations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      applied_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `)

  const applied = new Set(
    db.prepare('SELECT name FROM migrations').pluck().all() as string[]
  )

  const migrationsDir = new URL('./migrations', import.meta.url).pathname
  const files = readdirSync(migrationsDir)
    .filter((f) => f.endsWith('.sql'))
    .sort()

  for (const file of files) {
    if (applied.has(file)) continue

    const sql = readFileSync(join(migrationsDir, file), 'utf8')
    db.transaction(() => {
      db.exec(sql)
      db.prepare('INSERT INTO migrations (name) VALUES (?)').run(file)
    })()

    console.log(`[migrate] applied ${file}`)
  }
}

export function ensureSchema() {
  const db = getDb()
  const schemaSql = readFileSync(
    new URL('./schema.sql', import.meta.url).pathname,
    'utf8'
  )
  db.exec(schemaSql)
}

if (import.meta.url.startsWith('file:') && process.argv[1] === new URL(import.meta.url).pathname) {
  ensureSchema()
  runMigrations()
  console.log('[migrate] done')
}
