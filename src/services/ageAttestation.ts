/**
 * Issuer-side age facts from the INE birth date (CD-16).
 *
 * The age claims an enrollment carries (`age_over_18`, `age_over_21`) are
 * decided here, from the birth date on the INE record, to the day. The
 * client's Groth16 age proof no longer decides them: its `birthYear` is a
 * witness the client chooses, so it can only ever show that *some* year
 * satisfies the threshold (THREAT_MODEL gap 8). The proof still contributes
 * the enrollment commitment.
 *
 * Days are counted from DAY_EPOCH (1900-01-01), not the Unix epoch, so every
 * birth day of a living person is a small non-negative integer — the form the
 * v3 age circuit takes them in as field elements (`V3_UNLINKABLE_AGE_PROOFS.md`).
 */

const DAY_MS = 86_400_000

/** Day 0 of the issuer day count. */
export const DAY_EPOCH = { year: 1900, month: 1, day: 1 } as const
const DAY_EPOCH_MS = Date.UTC(DAY_EPOCH.year, DAY_EPOCH.month - 1, DAY_EPOCH.day)

/**
 * The issuer's "today" is the calendar date in the westernmost Mexican time
 * zone, the last one to reach any given date. A birthday therefore never
 * counts anywhere in Mexico before it has begun everywhere in Mexico: the
 * issuer is never early, at the cost of being up to a few hours late in the
 * eastern zones.
 */
export const ISSUER_TIME_ZONE = 'America/Tijuana'

export interface CivilDate {
  year: number
  /** 1–12 */
  month: number
  /** 1–31 */
  day: number
}

const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})$/

function daysInMonth(year: number, month: number): number {
  return new Date(Date.UTC(year, month, 0)).getUTCDate()
}

/** Strict `YYYY-MM-DD` that names a real calendar date, or null. */
export function parseCivilDate(value: unknown): CivilDate | null {
  if (typeof value !== 'string') return null
  const match = ISO_DATE.exec(value)
  if (!match) return null
  const year = Number(match[1])
  const month = Number(match[2])
  const day = Number(match[3])
  if (month < 1 || month > 12) return null
  if (day < 1 || day > daysInMonth(year, month)) return null
  return { year, month, day }
}

/** Days since DAY_EPOCH. Negative before it. */
export function dayNumber(date: CivilDate): number {
  return Math.round((Date.UTC(date.year, date.month - 1, date.day) - DAY_EPOCH_MS) / DAY_MS)
}

/** The calendar date at `now` in ISSUER_TIME_ZONE. */
export function issuerToday(now: Date = new Date()): CivilDate {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: ISSUER_TIME_ZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).formatToParts(now)
  const get = (type: string) => Number(parts.find((part) => part.type === type)!.value)
  return { year: get('year'), month: get('month'), day: get('day') }
}

/**
 * The last birth day (as a day number) of someone who is at least `years` old
 * on `today`. The anniversary of 29 February in a common year is 28 February
 * here: the target date is clamped to the end of its month, so nobody born on
 * 1 March counts a day early. The v3 verifier computes the same value outside
 * the circuit, which keeps leap years out of it.
 */
export function cutoffDay(today: CivilDate, years: number): number {
  const year = today.year - years
  const day = Math.min(today.day, daysInMonth(year, today.month))
  return dayNumber({ year, month: today.month, day })
}

export type IneAgeAttestation =
  | {
      ok: true
      /** Birth day number from the INE record. */
      birthDay: number
      /** The issuer's today, as a day number. */
      today: number
      over18: boolean
      over21: boolean
    }
  | { ok: false; reason: 'birth_date_invalid' }

/**
 * Age facts the issuer attests from an INE record's birth date. A birth date
 * that does not parse, lies in the future, or precedes DAY_EPOCH is refused
 * outright rather than read as some age.
 */
export function attestAgeFromIneBirthDate(birthDate: unknown, now: Date = new Date()): IneAgeAttestation {
  const birth = parseCivilDate(birthDate)
  if (!birth) return { ok: false, reason: 'birth_date_invalid' }
  const birthDay = dayNumber(birth)
  const todayDate = issuerToday(now)
  const today = dayNumber(todayDate)
  if (birthDay < 0 || birthDay > today) return { ok: false, reason: 'birth_date_invalid' }
  return {
    ok: true,
    birthDay,
    today,
    over18: birthDay <= cutoffDay(todayDate, 18),
    over21: birthDay <= cutoffDay(todayDate, 21),
  }
}
