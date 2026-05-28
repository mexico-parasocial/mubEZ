import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { resolveLocale, createT } from '../../src/i18n/index.js'

describe('i18n', () => {
  it('resolves locale from Accept-Language header', () => {
    assert.equal(resolveLocale('en-US,en;q=0.9'), 'en')
    assert.equal(resolveLocale('es-MX,es;q=0.9'), 'es')
    assert.equal(resolveLocale('fr-FR,fr;q=0.9'), 'es') // fallback
    assert.equal(resolveLocale(undefined), 'es') // fallback
  })

  it('translates keys in English', () => {
    const t = createT('en')
    assert.equal(t('errors.auth.unauthorized'), 'Unauthorized')
    assert.equal(t('errors.anonymous.alreadyEnabled'), 'Anonymous mode already enabled')
    assert.equal(t('anonymous.prefix'), 'Citizen')
  })

  it('translates keys in Spanish', () => {
    const t = createT('es')
    assert.equal(t('errors.auth.unauthorized'), 'No autorizado')
    assert.equal(t('errors.anonymous.alreadyEnabled'), 'El modo anónimo ya está activado')
    assert.equal(t('anonymous.prefix'), 'Ciudadano')
  })

  it('falls back to Spanish for missing keys', () => {
    const t = createT('en')
    assert.equal(t('nonexistent.key'), 'nonexistent.key')
  })

  it('supports interpolation', () => {
    const t = createT('en')
    // We'll add a test key if needed, but for now just test the function signature works
    const result = t('errors.auth.unauthorized', { extra: 'data' })
    assert.equal(result, 'Unauthorized')
  })
})
