import { createHash, randomUUID } from 'node:crypto'
import type { IneExtractedData, IneVerificationResult } from '../types/index.js'

// ─── Deterministic pseudo-random from seed ─────────────────────────────────

function seededRandom(seed: string) {
  let state = 0
  for (let i = 0; i < seed.length; i++) {
    state = (state * 31 + seed.charCodeAt(i)) >>> 0
  }
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0
    return state / 0xffffffff
  }
}

function pick<T>(rng: () => number, arr: T[]): T {
  return arr[Math.floor(rng() * arr.length)]
}

// ─── Mexican name database ─────────────────────────────────────────────────

const FIRST_NAMES_M = [
  'José', 'Juan', 'Luis', 'Carlos', 'Francisco', 'Javier', 'Miguel', 'Antonio',
  'Alejandro', 'Pedro', 'Daniel', 'Fernando', 'Jorge', 'Ricardo', 'Manuel',
  'Eduardo', 'Roberto', 'Andrés', 'Sergio', 'Raúl', 'Arturo', 'Héctor',
  'Martín', 'Gabriel', 'Diego', 'Pablo', 'Enrique', 'Oscar', 'Guillermo',
  'Ramón', 'Rubén', 'Víctor', 'Armando', 'Jaime', 'César', 'Julio',
  'Mario', 'Salvador', 'Gerardo', 'Ernesto', 'Rodrigo', 'Ismael', 'Marco',
  'Tomás', 'Alfredo', 'Agustín', 'Felipe', 'Adrián', 'Gustavo', 'Ignacio',
]

const FIRST_NAMES_F = [
  'María', 'Guadalupe', 'Margarita', 'Rosa', 'Laura', 'Patricia', 'Alejandra',
  'Ana', 'Carmen', 'Elizabeth', 'Josefina', 'Lucía', 'Verónica', 'Diana',
  'Gabriela', 'Silvia', 'Norma', 'Adriana', 'Leticia', 'Irma', 'Alma',
  'Martha', 'Yolanda', 'Alicia', 'Andrea', 'Claudia', 'Susana', 'Isabel',
  'Mariana', 'Fernanda', 'Natalia', 'Paola', 'Daniela', 'Erika', 'Mónica',
  'Julia', 'Araceli', 'Lorena', 'Cristina', 'Raquel', 'Beatriz', 'Rocío',
  'Sonia', 'Karla', 'Liliana', 'Teresa', 'Elena', 'Ruth', 'Olivia',
]

const LAST_NAMES = [
  'Hernández', 'García', 'Martínez', 'López', 'González', 'Pérez', 'Rodríguez',
  'Sánchez', 'Ramírez', 'Cruz', 'Flores', 'Gómez', 'Morales', 'Vásquez',
  'Jiménez', 'Reyes', 'Díaz', 'Torres', 'Gutiérrez', 'Ruiz', 'Mendoza',
  'Aguilar', 'Méndez', 'Castillo', 'Vargas', 'Moreno', 'Ortiz', 'Silva',
  'Romero', 'Herrera', 'Medina', 'Ramos', 'Castro', 'Rivera', 'Chávez',
  'Rojas', 'Domínguez', 'Guerrero', 'Contreras', 'Salazar', 'Espinoza',
  'Valdez', 'Cortés', 'Santiago', 'Ávila', 'Campos', 'Vega', 'Miranda',
  'Cárdenas', 'Espinosa', 'Soto', 'Delgado', 'Navarro', 'Fuentes', 'Sandoval',
  'Ayala', 'Marín', 'Mora', 'León', 'Ibarra', 'Mejía', 'Cabrera',
  'Camacho', 'Rosas', 'Núñez', 'Peña', 'Padilla', 'Pacheco', 'Alvarado',
  'Maldonado', 'Villegas', 'Santos', 'Valencia', 'Arroyo', 'Esparza',
  'Bautista', 'Acevedo', 'Mata', 'Ponce', 'Zúñiga', 'Calderón', 'Quintero',
  'Salas', 'Gallegos', 'Barajas', 'Arellano', 'Meléndez', 'Valenzuela',
  'Franco', 'Treviño', 'Ríos', 'Casillas', 'Luna', 'Sierra', 'Galván',
  'de la Cruz', 'Villarreal', 'Cano', 'Benítez', 'Escobar', 'Cervantes',
  'Bravo', 'Solís', 'Aguirre', 'Velázquez', 'Rangel', 'Tapia', 'Olvera',
]

const STATES = [
  { name: 'Aguascalientes', code: 'AS', cities: ['Aguascalientes', 'Jesús María', 'Calvillo'] },
  { name: 'Baja California', code: 'BC', cities: ['Tijuana', 'Mexicali', 'Ensenada', 'Rosarito'] },
  { name: 'Baja California Sur', code: 'BS', cities: ['La Paz', 'Cabo San Lucas', 'San José del Cabo'] },
  { name: 'Campeche', code: 'CC', cities: ['Campeche', 'Ciudad del Carmen', 'Champotón'] },
  { name: 'Coahuila', code: 'CL', cities: ['Saltillo', 'Torreón', 'Monclova', 'Piedras Negras'] },
  { name: 'Colima', code: 'CM', cities: ['Colima', 'Manzanillo', 'Villa de Álvarez'] },
  { name: 'Chiapas', code: 'CS', cities: ['Tuxtla Gutiérrez', 'San Cristóbal de las Casas', 'Tapachula'] },
  { name: 'Chihuahua', code: 'CH', cities: ['Chihuahua', 'Ciudad Juárez', 'Delicias', 'Hidalgo del Parral'] },
  { name: 'Ciudad de México', code: 'DF', cities: ['Coyoacán', 'Iztapalapa', 'Álvaro Obregón', 'Benito Juárez', 'Miguel Hidalgo'] },
  { name: 'Durango', code: 'DG', cities: ['Durango', 'Gómez Palacio', 'Lerdo'] },
  { name: 'Guanajuato', code: 'GT', cities: ['León', 'Irapuato', 'Celaya', 'Guanajuato'] },
  { name: 'Guerrero', code: 'GR', cities: ['Acapulco', 'Chilpancingo', 'Iguala'] },
  { name: 'Hidalgo', code: 'HG', cities: ['Pachuca', 'Tulancingo', 'Tula de Allende'] },
  { name: 'Jalisco', code: 'JC', cities: ['Guadalajara', 'Zapopan', 'Tlaquepaque', 'Tonalá', 'Puerto Vallarta'] },
  { name: 'México', code: 'MC', cities: ['Toluca', 'Naucalpan', 'Ecatepec', 'Tlalnepantla', 'Chalco'] },
  { name: 'Michoacán', code: 'MN', cities: ['Morelia', 'Uruapan', 'Lázaro Cárdenas'] },
  { name: 'Morelos', code: 'MS', cities: ['Cuernavaca', 'Jiutepec', 'Cuautla'] },
  { name: 'Nayarit', code: 'NT', cities: ['Tepic', 'Bahía de Banderas', 'Santiago Ixcuintla'] },
  { name: 'Nuevo León', code: 'NL', cities: ['Monterrey', 'San Pedro Garza García', 'Guadalupe', 'Apodaca', 'San Nicolás'] },
  { name: 'Oaxaca', code: 'OC', cities: ['Oaxaca de Juárez', 'Salina Cruz', 'Juchitán'] },
  { name: 'Puebla', code: 'PL', cities: ['Puebla', 'San Martín Texmelucan', 'Tehuacán'] },
  { name: 'Querétaro', code: 'QT', cities: ['Querétaro', 'San Juan del Río', 'Corregidora'] },
  { name: 'Quintana Roo', code: 'QR', cities: ['Cancún', 'Playa del Carmen', 'Chetumal'] },
  { name: 'San Luis Potosí', code: 'SP', cities: ['San Luis Potosí', 'Soledad de Graciano Sánchez', 'Matehuala'] },
  { name: 'Sinaloa', code: 'SL', cities: ['Culiacán', 'Mazatlán', 'Los Mochis'] },
  { name: 'Sonora', code: 'SR', cities: ['Hermosillo', 'Ciudad Obregón', 'Nogales'] },
  { name: 'Tabasco', code: 'TC', cities: ['Villahermosa', 'Cárdenas', 'Comalcalco'] },
  { name: 'Tamaulipas', code: 'TS', cities: ['Tampico', 'Ciudad Victoria', 'Reynosa', 'Matamoros', 'Nuevo Laredo'] },
  { name: 'Tlaxcala', code: 'TL', cities: ['Tlaxcala', 'Apizaco', 'Chiautempan'] },
  { name: 'Veracruz', code: 'VZ', cities: ['Veracruz', 'Xalapa', 'Coatzacoalcos', 'Poza Rica'] },
  { name: 'Yucatán', code: 'YN', cities: ['Mérida', 'Valladolid', 'Progreso'] },
  { name: 'Zacatecas', code: 'ZS', cities: ['Zacatecas', 'Fresnillo', 'Guadalupe'] },
]

const STREET_NAMES = [
  'Av. Insurgentes', 'Calle Hidalgo', 'Av. Juárez', 'Calle Morelos',
  'Av. Reforma', 'Calle Independencia', 'Av. Madero', 'Calle Allende',
  'Av. Universidad', 'Calle Zaragoza', 'Av. Constitución', 'Calle Guerrero',
  'Av. Revolución', 'Calle Aldama', 'Av. 5 de Mayo', 'Calle Bravo',
  'Av. Central', 'Calle Victoria', 'Av. Pino Suárez', 'Calle Obregón',
  'Av. Chapultepec', 'Calle Lerdo', 'Av. del Trabajo', 'Calle Mina',
  'Av. de los Maestros', 'Calle Matamoros', 'Av. Las Torres', 'Calle Palma',
]

const NEIGHBORHOODS = [
  'Centro', 'Las Águilas', 'Jardines', 'San Rafael', 'El Carmen',
  'La Paz', 'San Pedro', 'Vista Hermosa', 'El Dorado', 'Los Pinos',
  'Santa María', 'La Aurora', 'San José', 'Las Flores', 'El Mirador',
  'La Esperanza', 'San Antonio', 'Las Lomas', 'El Progreso', 'La Providencia',
]

// ─── CURP helpers ──────────────────────────────────────────────────────────

const CURP_VOWELS = 'AEIOU'
const CURP_CONSONANTS = 'BCDFGHJKLMNPQRSTVWXYZ'
const CURP_BAD_WORDS = new Set(['BACA', 'BAKA', 'BUEI', 'BUEY', 'CACA', 'CACO', 'CAGA', 'CAGO', 'CAKA', 'CAKO', 'COGE', 'COGI', 'COJA', 'COJE', 'COJI', 'COJO', 'COLA', 'CULO', 'FALO', 'FETO', 'GETA', 'GUEI', 'GUEY', 'JETA', 'JOTO', 'KACA', 'KACO', 'KAGA', 'KAGO', 'KAKA', 'KAKO', 'KOGE', 'KOGI', 'KOJA', 'KOJE', 'KOJI', 'KOJO', 'KOLA', 'KULO', 'LILO', 'LOCA', 'LOCO', 'LOKA', 'LOKO', 'MAME', 'MAMO', 'MEAR', 'MEAS', 'MEON', 'MIAR', 'MION', 'MOCO', 'MOKO', 'MULA', 'MULO', 'NACA', 'NACO', 'PEDA', 'PEDO', 'PENE', 'PIPI', 'PITO', 'POPO', 'PUTA', 'PUTO', 'QULO', 'RATA', 'ROBA', 'ROBE', 'ROBO', 'RUIN', 'SENO', 'TETA', 'VACA', 'VAGA', 'VAGO', 'VAKA', 'VAGO', 'VUEI', 'VUEY', 'WUEI', 'WUEY'])

function firstConsonant(str: string): string {
  for (const c of str.toUpperCase()) {
    if (CURP_CONSONANTS.includes(c)) return c
  }
  return 'X'
}

function firstVowel(str: string): string {
  for (const c of str.toUpperCase()) {
    if (CURP_VOWELS.includes(c)) return c
  }
  return 'X'
}

function curpNameCode(paternal: string, maternal: string, firstName: string): string {
  const p1 = paternal.charAt(0).toUpperCase()
  const p2 = firstVowel(paternal.slice(1))
  const m1 = maternal.charAt(0).toUpperCase()
  const n1 = firstName.charAt(0).toUpperCase()
  const code = `${p1}${p2}${m1}${n1}`
  if (CURP_BAD_WORDS.has(code)) return `${p1}X${m1}${n1}`
  return code
}

function curpBirthCode(birthDate: string, gender: 'M' | 'F'): string {
  const d = new Date(birthDate)
  const yy = d.getFullYear().toString().slice(-2)
  const mm = String(d.getMonth() + 1).padStart(2, '0')
  const dd = String(d.getDate()).padStart(2, '0')
  return `${yy}${mm}${dd}${gender}`
}

function curpStateCode(stateName: string): string {
  const state = STATES.find(s => s.name === stateName)
  return state?.code ?? 'NE'
}

function curpCheckDigit(curp17: string): string {
  const VALUES = '0123456789ABCDEFGHIJKLMNÑOPQRSTUVWXYZ'
  const MAP: Record<string, number> = {}
  for (let i = 0; i < VALUES.length; i++) MAP[VALUES[i]] = i
  let sum = 0
  for (let i = 0; i < 17; i++) {
    const val = MAP[curp17[i].toUpperCase()] ?? 0
    sum += val * (18 - i)
  }
  const rem = sum % 10
  return String((10 - rem) % 10)
}

function generateCurp(
  firstName: string,
  paternal: string,
  maternal: string,
  birthDate: string,
  gender: 'M' | 'F',
  stateName: string,
): string {
  const nameCode = curpNameCode(paternal, maternal, firstName)
  const birthCode = curpBirthCode(birthDate, gender)
  const stateCode = curpStateCode(stateName)
  const pConsonant = firstConsonant(paternal.slice(1))
  const mConsonant = firstConsonant(maternal.slice(1))
  const nConsonant = firstConsonant(firstName.slice(1))
  const base = `${nameCode}${birthCode}${stateCode}${pConsonant}${mConsonant}${nConsonant}0`
  const check = curpCheckDigit(base)
  return `${base}${check}`
}

// ─── Voter ID helpers ──────────────────────────────────────────────────────

function generateVoterId(rng: () => number): string {
  const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  const l1 = letters[Math.floor(rng() * 26)]
  const l2 = letters[Math.floor(rng() * 26)]
  const l3 = letters[Math.floor(rng() * 26)]
  const num = String(Math.floor(rng() * 999999)).padStart(6, '0')
  const l4 = letters[Math.floor(rng() * 26)]
  const check = String(Math.floor(rng() * 9))
  return `${l1}${l2}${l3}${num}${l4}${check}`
}

// ─── Simulation engine ─────────────────────────────────────────────────────

export function simulateIneExtraction(payloadBase64: string): {
  extracted: IneExtractedData
  ocrConfidence: number
  extractionStatus: 'complete' | 'partial' | 'failed'
  missingFields: string[]
} {
  const seed = createHash('sha256').update(payloadBase64).digest('hex')
  const rng = seededRandom(seed)

  const gender = rng() > 0.5 ? 'M' : 'F'
  const firstNames = gender === 'M' ? FIRST_NAMES_M : FIRST_NAMES_F
  const firstName = pick(rng, firstNames)
  const paternal = pick(rng, LAST_NAMES)
  const maternal = pick(rng, LAST_NAMES)
  const fullName = `${firstName} ${paternal} ${maternal}`

  // Birth date: 18-65 years ago
  const now = new Date()
  const minAge = 18
  const maxAge = 65
  const ageYears = minAge + Math.floor(rng() * (maxAge - minAge))
  const birthYear = now.getFullYear() - ageYears
  const birthMonth = Math.floor(rng() * 12)
  const birthDay = 1 + Math.floor(rng() * 28)
  const birthDate = new Date(birthYear, birthMonth, birthDay).toISOString().split('T')[0]

  const state = pick(rng, STATES)
  const city = pick(rng, state.cities)
  const street = pick(rng, STREET_NAMES)
  const neighborhood = pick(rng, NEIGHBORHOODS)
  const streetNum = 10 + Math.floor(rng() * 990)
  const postalCode = String(10000 + Math.floor(rng() * 70000)).padStart(5, '0')

  const curp = generateCurp(firstName, paternal, maternal, birthDate, gender, state.name)
  const voterId = generateVoterId(rng)

  const extracted: IneExtractedData = {
    fullName,
    firstName,
    lastNamePaternal: paternal,
    lastNameMaternal: maternal,
    curp,
    voterId,
    birthDate,
    gender,
    address: {
      street: `${street} ${streetNum}`,
      neighborhood,
      city,
      state: state.name,
      postalCode,
    },
    photoHash: createHash('sha256').update(seed + 'ine-photo').digest('hex'),
    expiryYear: now.getFullYear() + (4 + Math.floor(rng() * 6)),
  }

  const ocrConfidence = 0.91 + rng() * 0.08 // 0.91 - 0.99
  const extractionStatus = ocrConfidence > 0.85 ? 'complete' : 'partial'
  const missingFields: string[] = extractionStatus === 'complete' ? [] : ['neighborhood']

  return { extracted, ocrConfidence, extractionStatus, missingFields }
}

export function simulateIneVerification(
  extracted: IneExtractedData,
  selfieBase64: string,
): IneVerificationResult {
  const seed = createHash('sha256').update(extracted.curp + selfieBase64).digest('hex')
  const rng = seededRandom(seed)

  // Face match: deterministic but different from photo hash
  const selfieHash = createHash('sha256').update(selfieBase64).digest('hex')
  const photoHashNum = parseInt(extracted.photoHash.slice(0, 8), 16)
  const selfieHashNum = parseInt(selfieHash.slice(0, 8), 16)
  const hashDiff = Math.abs(photoHashNum - selfieHashNum) / 0xffffffff
  const faceMatchScore = Math.min(0.99, 0.82 + (1 - hashDiff) * 0.15 + rng() * 0.03)

  // RENAPO simulation
  const renapoStatus: IneVerificationResult['renapo']['status'] = rng() > 0.05 ? 'active' : pick(rng, ['deceased', 'not-found', 'duplicate'])
  const renapoMatched = renapoStatus === 'active'

  const overall: IneVerificationResult['overall'] =
    faceMatchScore >= 0.80 && renapoMatched
      ? 'verified'
      : faceMatchScore >= 0.70 && renapoMatched
        ? 'manual-review-required'
        : 'rejected'

  return {
    faceMatch: {
      score: Math.round(faceMatchScore * 100) / 100,
      threshold: 0.80,
      passed: faceMatchScore >= 0.80,
    },
    renapo: {
      status: renapoStatus,
      registeredName: extracted.fullName,
      registeredCurp: extracted.curp,
      citizenship: 'MX',
      matched: renapoMatched,
    },
    overall,
    verificationId: `ine-verify-${randomUUID()}`,
    verifiedAt: new Date().toISOString(),
  }
}
