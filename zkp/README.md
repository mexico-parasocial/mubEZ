# ZKP Stack — INE Age Proof

This directory contains a minimal but functional **zero-knowledge proof circuit** that demonstrates the core privacy architecture of PARA.

## What it proves

The `IneAgeProof` circuit proves that the prover knows a `birthYear` and `salt` such that:

1. `commitment = Poseidon(birthYear, salt)`
2. `birthYear <= currentYear - ageThreshold`

In plain terms: **"I am at least X years old"** without revealing the exact birth year.

## Circuit details

| Property | Value |
|---|---|
| File | `circuits/ine_age_proof.circom` |
| Protocol | Groth16 |
| Curve | BN254 |
| Constraints | ~260 non-linear |
| Public inputs | `currentYear`, `ageThreshold` |
| Private inputs | `birthYear`, `salt` |
| Public output | `commitment` |

## Quick start

```bash
cd muvis/zkp/scripts
./setup.sh
```

This script:
1. Compiles the circuit (`circom` → `.r1cs`, `.wasm`, `.sym`)
2. Downloads the Powers of Tau file (`pot12.ptau`, ~4.7 MB)
3. Runs the Groth16 trusted setup
4. Exports the verification key
5. Generates a test proof and verifies it

## Generated artifacts

All generated files live in `zkp/out/` (gitignored):

| File | Purpose |
|---|---|
| `ine_age_proof.r1cs` | Rank-1 constraint system |
| `ine_age_proof_js/ine_age_proof.wasm` | WASM witness generator |
| `ine_age_proof.sym` | Symbol file (for debugging) |
| `pot12.ptau` | Powers of Tau for trusted setup |
| `ine_age_proof_final.zkey` | Proving key (keep secret!) |
| `verification_key.json` | Verification key (can be public) |

## Test artifacts (insecure, committed)

The production `*.wasm` and `*.zkey` are not in git, and their phase 2 used
random entropy, so they cannot be rebuilt to match the pins in
`artifact-manifest.json`. Tests prove against a separate set instead:

| | |
|---|---|
| Files | `test-artifacts/*_test.{wasm,zkey}`, `test-artifacts/*_test_vkey.json` |
| Manifest | `artifact-manifest.test.json` (`testOnly: true`), which also pins the circuit sources |
| Selected by | `ZKP_ARTIFACT_SET=test` (set by `pnpm test:integration`, `pnpm test:e2e` and CI) |
| Rebuild | `CIRCOM="npx circom2" CIRCOMLIB_DIR=<circomlib 2.x> pnpm zkp:test-artifacts` |

**Anyone can forge proofs against these keys**: every setup contribution
uses published entropy. So `ZKP_ARTIFACT_SET=test` is refused when
`NODE_ENV=production`, both at boot (`start/env.ts`) and at load
(`src/services/zkpArtifacts.ts`). The files are kept out of the build
(`adonisrc.ts` copies only the production set) and out of the image
(`.dockerignore`). A test-key proof does not verify under the production
vkey (`tests/unit/zkp-artifacts.test.ts`).

After changing a circuit, rebuild the set: the unit test fails while
`artifact-manifest.test.json` pins an older source.

## Integration with INE flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────────────┐
│   INE API   │────▶│   m8 backend │────▶│  ZKP Circuit (circom)│
│  (future)   │     │              │     │                      │
└─────────────┘     └─────────────┘     └─────────────────────┘
                                               │
                                               ▼
                                        ┌─────────────┐
                                        │  snarkjs    │
                                        │  (generate) │
                                        └─────────────┘
                                               │
                                               ▼
                                        ┌─────────────┐
                                        │   User      │
                                        │  (device)   │
                                        └─────────────┘
```

### Current state (demo)
- The backend generates the proof (`generateAgeProof`)
- Useful for integration tests and validating the stack

### Production path
- The user's device (React Native or web) receives the `.wasm` and `.zkey`
- The device generates the proof locally with `snarkjs` — the server never sees `birthYear` or `salt`
- The device sends only `proof + publicSignals` to the verifier

## Testing

Run the ZKP integration tests:

```bash
cd muvis
npx tsx --test tests/integration/zkp.test.ts
```

Tests cover:
- Valid proof generation and verification
- Rejection of underage citizens (circuit assertion failure)
- Tamper detection (modified public signals fail verification)

## Architecture notes

### Why Groth16?
- Fastest proof generation and verification
- Small proof size (~192 bytes)
- Mature tooling (circom + snarkjs)
- Trade-off: requires a **trusted setup** per circuit

### Why not PLONK or STARKs?
- PLONK: no per-circuit trusted setup, but larger proofs and slower verification
- STARKs: no trusted setup at all, but proofs are ~50-100x larger
- For a mobile app, Groth16's small proofs are a significant advantage
- We can migrate to PLONK later without changing the circuit logic

### Why Poseidon?
- ZK-friendly hash function (few constraints in circom)
- Standard in zk-SNARK ecosystems (Semaphore, Tornado Cash, etc.)
- ~260 constraints for Poseidon(2) + LessEqThan(16)
- SHA-256 would require ~25,000+ constraints

## Next steps

1. **Client-side proving**: Move `generateAgeProof` to the React Native app
2. **CURP circuit v2**: Add a circuit that proves knowledge of a CURP whose hash is in a Merkle tree of verified citizens
3. **Nullifiers**: Add `nullifier = Poseidon(secret, context)` to prevent double-registration
4. **CRL integration**: Prove non-inclusion in a Merkle tree of revoked credentials
