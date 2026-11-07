#!/bin/bash
# Builds the TEST-ONLY ZKP artifact set in zkp/test-artifacts/ and its
# manifest, zkp/artifact-manifest.test.json.
#
# Why this exists: the production artifacts (zkp/out/*.wasm, *.zkey) are not
# in git, and their Groth16 phase 2 used random entropy, so they cannot be
# rebuilt to match the pins in zkp/artifact-manifest.json. Tests that prove
# need *some* wasm/zkey/vkey for the same circuits; this is that set.
#
# INSECURE BY DESIGN. Every contribution below uses fixed, published entropy,
# so anyone can forge proofs against these keys. They are loaded only with
# ZKP_ARTIFACT_SET=test, which src/services/zkpArtifacts.ts refuses in
# production, and they are kept out of the build and the image.
#
# Never writes to zkp/out/. Rerun after changing a circuit: the test manifest
# pins the circuit sources, and tests/unit/zkp-artifacts.test.ts fails until
# the set is rebuilt.
#
# Needs: circom 2 (`circom`, or CIRCOM="npx circom2"), and circomlib 2.x
# circuits (CIRCOMLIB_DIR, e.g. node_modules/circomlib).
set -euo pipefail

ZKP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ROOT_DIR="$(cd "${ZKP_DIR}/.." && pwd)"
OUT_DIR="${ZKP_DIR}/test-artifacts"
SNARKJS="${ROOT_DIR}/node_modules/.bin/snarkjs"
CIRCOM="${CIRCOM:-circom}"
: "${CIRCOMLIB_DIR:?set CIRCOMLIB_DIR to a circomlib 2.x checkout or package}"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# A work copy of the circuits with circomlib beside them. circom2 (WASI)
# cannot resolve ".." in include paths, so the copy includes "circomlib/..."
# instead of "../circomlib/...". Nothing else in the sources changes, and the
# manifest pins the unmodified files in zkp/circuits/.
mkdir -p "${WORK}/circuits/circomlib" "${WORK}/circuits/lib"
cp "${ZKP_DIR}"/circuits/*.circom "${WORK}/circuits/"
cp "${ZKP_DIR}"/circuits/lib/*.circom "${WORK}/circuits/lib/"
cp -R "${CIRCOMLIB_DIR}/circuits" "${WORK}/circuits/circomlib/circuits"
# Top-level circuits include circomlib as a sibling; the files in lib/ (which
# sit one directory deeper) are rewritten the same way and resolved through
# the "-l ." library path below, because ".." cannot be resolved either.
sed -i.orig 's#include "../circomlib/#include "circomlib/#' "${WORK}"/circuits/*.circom
sed -i.orig 's#include "../../circomlib/#include "circomlib/#' "${WORK}"/circuits/lib/*.circom

# 2^15: nullifier_proof_v2 has ~8.4k constraints, and snarkjs needs 2 * constraints <= 2^power.
POT_POWER=15
echo "=== Powers of tau (2^${POT_POWER}, fixed entropy) ==="
"${SNARKJS}" powersoftau new bn128 "${POT_POWER}" "${WORK}/pot_0000.ptau"
"${SNARKJS}" powersoftau contribute "${WORK}/pot_0000.ptau" "${WORK}/pot_0001.ptau" \
  --name="mubez-test-only-INSECURE" -e="mubez test artifacts: public entropy, not secure"
"${SNARKJS}" powersoftau prepare phase2 "${WORK}/pot_0001.ptau" "${WORK}/pot_final.ptau"

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

for name in ine_age_proof nullifier_proof_v2; do
  echo "=== ${name} ==="
  (cd "${WORK}/circuits" && ${CIRCOM} "${name}.circom" -l . --r1cs --wasm -o "${WORK}")
  "${SNARKJS}" groth16 setup "${WORK}/${name}.r1cs" "${WORK}/pot_final.ptau" "${WORK}/${name}_0000.zkey"
  "${SNARKJS}" zkey contribute "${WORK}/${name}_0000.zkey" "${OUT_DIR}/${name}_test.zkey" \
    --name="mubez-test-only-INSECURE" -e="mubez ${name} test key: public entropy, not secure"
  "${SNARKJS}" zkey export verificationkey "${OUT_DIR}/${name}_test.zkey" "${OUT_DIR}/${name}_test_vkey.json"
  cp "${WORK}/${name}_js/${name}.wasm" "${OUT_DIR}/${name}_test.wasm"
done

echo "=== Manifest ==="
node "${ZKP_DIR}/scripts/write-test-manifest.mjs"
echo "✓ test artifacts in ${OUT_DIR}"
