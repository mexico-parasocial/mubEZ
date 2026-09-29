#!/bin/bash
set -euo pipefail

# DEVELOPMENT ONLY. The Groth16 phase 2 below has a single contributor, who
# could forge proofs. Production keys come from the multi-party ceremony in
# docs/ZK_CEREMONY_PLAN.md. After regenerating, update the sha256 digests in
# zkp/artifact-manifest.json.

cd "$(dirname "$0")/.."

OUTDIR="out"
SNARKJS="../node_modules/.bin/snarkjs"

compile_circuit() {
  local name="$1"
  echo "=== Compiling ${name} ==="
  # --O2 removes linear constraints, which keeps nullifier_proof_v2 inside
  # the 2^12 Powers of Tau used here.
  circom "circuits/${name}.circom" --O2 --r1cs --wasm --sym -o "${OUTDIR}"
}

trusted_setup() {
  local name="$1"
  local pot="${OUTDIR}/pot12.ptau"

  if [ ! -f "${pot}" ]; then
    echo "Downloading pot12.ptau (~4.7 MB)..."
    curl -L -o "${pot}" "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_12.ptau"
  fi

  echo "=== Groth16 setup for ${name} ==="
  "${SNARKJS}" groth16 setup "${OUTDIR}/${name}.r1cs" "${pot}" "${OUTDIR}/${name}_0000.zkey"

  echo "=== Contribute to ceremony ==="
  echo "para-dev-contribution" | "${SNARKJS}" zkey contribute \
    "${OUTDIR}/${name}_0000.zkey" \
    "${OUTDIR}/${name}_final.zkey" \
    --name="para-dev" -v

  echo "=== Export verification key ==="
  "${SNARKJS}" zkey export verificationkey \
    "${OUTDIR}/${name}_final.zkey" \
    "${OUTDIR}/${name}_vkey.json"

  if [ "${name}" != "ine_age_proof" ]; then
    # nullifier_proof_v2 needs a Merkle path; tests/integration/nullifier.test.ts
    # proves and verifies it against a real enrollment tree.
    echo "(no smoke test for ${name}; run the nullifier integration test)"
    return
  fi

  echo "=== Smoke test for ${name} ==="
  local test_input="${OUTDIR}/${name}_test_input.json"
  if [ "${name}" = "ine_age_proof" ]; then
    cat > "${test_input}" << 'EOF'
{
  "birthYear": 1985,
  "salt": 123456789,
  "currentYear": 2026,
  "ageThreshold": 18
}
EOF
  else
    cat > "${test_input}" << 'EOF'
{
  "birthYear": 1985,
  "salt": 123456789,
  "communityId": 42,
  "currentYear": 2026,
  "ageThreshold": 18
}
EOF
  fi

  "${SNARKJS}" wtns calculate \
    "${OUTDIR}/${name}_js/${name}.wasm" \
    "${test_input}" \
    "${OUTDIR}/${name}_witness.wtns"

  "${SNARKJS}" groth16 prove \
    "${OUTDIR}/${name}_final.zkey" \
    "${OUTDIR}/${name}_witness.wtns" \
    "${OUTDIR}/${name}_proof.json" \
    "${OUTDIR}/${name}_public.json"

  "${SNARKJS}" groth16 verify \
    "${OUTDIR}/${name}_vkey.json" \
    "${OUTDIR}/${name}_public.json" \
    "${OUTDIR}/${name}_proof.json"

  echo "✓ ${name} OK"
}

# Compile both circuits
compile_circuit "ine_age_proof"
compile_circuit "nullifier_proof_v2"

# Trusted setup for both (shares the same PTAU)
trusted_setup "ine_age_proof"
trusted_setup "nullifier_proof_v2"

echo ""
echo "=== ZKP setup complete ==="
echo "  Circuits compiled: ine_age_proof, nullifier_proof_v2"
echo "  Artifacts in: ${OUTDIR}/"
