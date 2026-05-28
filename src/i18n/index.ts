import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FALLBACK_LOCALE = 'es'

const locales = new Map<string, Record<string, string>>()

function loadLocale(locale: string): Record<string, string> {
  if (locales.has(locale)) return locales.get(locale)!
  try {
    const raw = readFileSync(join(__dirname, 'locales', `${locale}.json`), 'utf-8')
    const dict = JSON.parse(raw) as Record<string, string>
    locales.set(locale, dict)
    return dict
  } catch {
    return {}
  }
}

export function resolveLocale(acceptLanguage?: string): string {
  if (!acceptLanguage) return FALLBACK_LOCALE
  const primary = acceptLanguage.split(',')[0]?.trim().split('-')[0]
  if (primary && ['es', 'en'].includes(primary)) return primary
  return FALLBACK_LOCALE
}

export type TFunction = (key: string, vars?: Record<string, string>) => string

export function createT(locale: string): TFunction {
  const dict = loadLocale(locale)
  const fallback = locale === FALLBACK_LOCALE ? {} : loadLocale(FALLBACK_LOCALE)

  return (key: string, vars?: Record<string, string>): string => {
    let text = dict[key] ?? fallback[key] ?? key
    if (vars) {
      for (const [k, v] of Object.entries(vars)) {
        text = text.replace(new RegExp(`\\{${k}\\}`, 'g'), v)
      }
    }
    return text
  }
}
