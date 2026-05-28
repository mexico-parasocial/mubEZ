#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/.."

OUTDIR="out"
SNARKJS="../node_modules/.bin/snarkjs"

compile_circuit() {
  local name="$1"
  echo "=== Compiling ${name} ==="
  circom "circuits/${name}.circom" --r1cs --wasm --sym -o "${OUTDIR}"
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
compile_circuit "nullifier_proof"

# Trusted setup for both (shares the same PTAU)
trusted_setup "ine_age_proof"
trusted_setup "nullifier_proof"

echo ""
echo "=== ZKP setup complete ==="
echo "  Circuits compiled: ine_age_proof, nullifier_proof"
echo "  Artifacts in: ${OUTDIR}/"
