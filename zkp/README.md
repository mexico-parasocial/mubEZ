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
