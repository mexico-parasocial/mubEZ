import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  attestAgeFromIneBirthDate,
  cutoffDay,
  dayNumber,
  issuerToday,
  parseCivilDate,
} from '../../src/services/ageAttestation.js'

describe('issuer age attestation from the INE birth date (CD-16)', () => {
  it('parses only real calendar dates in strict YYYY-MM-DD', () => {
    assert.deepEqual(parseCivilDate('2000-02-29'), { year: 2000, month: 2, day: 29 })
    for (const bad of ['2001-02-29', '1900-02-29', '2000-13-01', '2000-00-10', '2000-04-31', '2000-1-01', '2000-01-01T00:00:00Z', ' 2000-01-01', '', 20000101, null, undefined]) {
      assert.equal(parseCivilDate(bad), null, String(bad))
    }
  })

  it('counts days from 1900-01-01', () => {
    assert.equal(dayNumber({ year: 1900, month: 1, day: 1 }), 0)
    assert.equal(dayNumber({ year: 1900, month: 3, day: 1 }), 59) // 1900 is not a leap year
    assert.equal(dayNumber({ year: 1970, month: 1, day: 1 }), 25567)
    assert.equal(dayNumber({ year: 2000, month: 3, day: 1 }) - dayNumber({ year: 2000, month: 2, day: 28 }), 2)
  })

  it('turns 18 on the birthday, not the day before', () => {
    const today = { year: 2026, month: 6, day: 15 }
    const cutoff = cutoffDay(today, 18)
    assert.equal(cutoff, dayNumber({ year: 2008, month: 6, day: 15 }))
    assert.ok(dayNumber({ year: 2008, month: 6, day: 16 }) > cutoff)
  })

  it('treats 29 February as 28 February in common years, never as 1 March', () => {
    // A leap day today, a common year N years back: the cutoff is 28 February.
    assert.equal(cutoffDay({ year: 2028, month: 2, day: 29 }, 18), dayNumber({ year: 2010, month: 2, day: 28 }))
    // Born on a leap day: not 18 on 28 February of a common year...
    const leapling = dayNumber({ year: 2008, month: 2, day: 29 })
    assert.ok(leapling > cutoffDay({ year: 2026, month: 2, day: 28 }, 18))
    // ...and 18 on 1 March.
    assert.ok(leapling <= cutoffDay({ year: 2026, month: 3, day: 1 }, 18))
  })

  it('takes today in the westernmost Mexican zone, so a birthday never counts early', () => {
    // 06:30 UTC on 15 June is still 14 June in Tijuana (UTC-7 in summer).
    assert.deepEqual(issuerToday(new Date('2026-06-15T06:30:00Z')), { year: 2026, month: 6, day: 14 })
    assert.deepEqual(issuerToday(new Date('2026-06-15T07:30:00Z')), { year: 2026, month: 6, day: 15 })

    const eve = attestAgeFromIneBirthDate('2008-06-15', new Date('2026-06-15T06:30:00Z'))
    const day = attestAgeFromIneBirthDate('2008-06-15', new Date('2026-06-15T07:30:00Z'))
    assert.ok(eve.ok && day.ok)
    assert.equal(eve.over18, false)
    assert.equal(day.over18, true)
    assert.equal(day.over21, false)
    assert.equal(day.birthDay, dayNumber({ year: 2008, month: 6, day: 15 }))
  })

  it('attests 21+ independently of 18+', () => {
    const now = new Date('2026-06-15T12:00:00Z')
    const twenty = attestAgeFromIneBirthDate('2006-01-01', now)
    const twentyOne = attestAgeFromIneBirthDate('2005-06-15', now)
    assert.ok(twenty.ok && twentyOne.ok)
    assert.deepEqual([twenty.over18, twenty.over21], [true, false])
    assert.deepEqual([twentyOne.over18, twentyOne.over21], [true, true])
  })

  it('refuses birth dates that are malformed, in the future, or before the day epoch', () => {
    const now = new Date('2026-06-15T12:00:00Z')
    for (const bad of ['not-a-date', '2026-06-16', '1899-12-31', '2007-02-29', undefined]) {
      assert.deepEqual(attestAgeFromIneBirthDate(bad, now), { ok: false, reason: 'birth_date_invalid' }, String(bad))
    }
  })
})
