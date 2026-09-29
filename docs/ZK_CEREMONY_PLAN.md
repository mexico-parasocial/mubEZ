# ZK setup ceremony plan

Status: **planned.** Covers the production Groth16 keys for
`nullifier_proof_v2` (CD-16) and `AgePresentationV3` (CD-15,
`V3_CIRCUIT_SPEC.md`). Today's keys come from `zkp/scripts/setup.sh`, a
single-party setup whose operator could forge proofs; they are development
keys only.

## Why a ceremony, and why after the audit

Groth16 needs a per-circuit setup (phase 2) on top of a universal one
(phase 1). Whoever knows the setup's randomness ("toxic waste") can forge
proofs: invent memberships, ages and nullifiers. A multi-party ceremony is
sound if at least one contributor destroyed their share.

A phase 2 is tied to the exact circuit. Any circuit change after the ceremony
voids it. So the order is fixed:

1. Audit the circuits (`ZK_AUDIT_RFP.md`) and fix the findings.
2. **Freeze.** Record the SHA-256 of every `.circom` file, the circom version,
   the compiler flags (`--O2`) and the resulting `.r1cs`. Change nothing after
   this point.
3. Run the ceremony.
4. Publish, then pin the artifacts in `zkp/artifact-manifest.json`.

## Sizes

| Circuit | Depth | Constraints (`--O2`) |
|---|---|---|
| `nullifier_proof_v2` | 20 | 5,372 |
| `AgePresentationV3` | 20 | 5,758 |

Both fit 2^13 = 8,192. **Use a phase 1 of power 14** (16,384) for headroom,
in case the audit adds constraints.

## Phase 1 (universal)

Reuse a public phase 1 with many contributors; don't run one. Options:

- **Perpetual Powers of Tau** (Privacy & Scaling Explorations), prepared for
  snarkjs at the needed power.
- **Hermez phase 1** (`powersOfTau28_hez_final_14.ptau`), already the family
  of `pot12.ptau` used in development.

Download it, check its hash against the value its maintainers published, and
record both in the transcript. The download needs your approval; nothing has
been downloaded for this plan.

## Phase 2 (per circuit)

### Tooling

- **snarkjs CLI.** `groth16 setup`, `zkey contribute`, `zkey verify`,
  `zkey beacon`, all already in `node_modules`. A coordinator hands the
  latest `.zkey` to each contributor.
- **p0tion** (PSE): runs a web-based phase 2 with queueing and verification.
  More setup, but less coordinator error and a public transcript page.

### Participants

- **At least 5 contributors**, from different organisations and
  jurisdictions: PARA/iM8 team, mubEZ maintainer, an independent
  cryptographer, a civil-society or academic participant, and the auditor if
  they agree. More is better; one honest contributor is enough.
- **Each contributor** uses a fresh or ephemeral machine (live USB or new
  VM), generates entropy locally, contributes, then wipes the machine. They
  publish a signed attestation with their contribution hash.

### Procedure (snarkjs)

```bash
# coordinator, once per circuit (frozen r1cs)
snarkjs groth16 setup nullifier_proof_v2.r1cs ppot_14.ptau nullifier_0000.zkey

# contributor i, on an ephemeral machine
snarkjs zkey contribute nullifier_000{i-1}.zkey nullifier_000{i}.zkey --name="<name>" -e="<local entropy>"

# coordinator, after every contribution
snarkjs zkey verify nullifier_proof_v2.r1cs ppot_14.ptau nullifier_000{i}.zkey

# final beacon: a public randomness value fixed in advance
snarkjs zkey beacon nullifier_000N.zkey nullifier_final.zkey <beacon hex> 10 -n="Final beacon"
snarkjs zkey export verificationkey nullifier_final.zkey nullifier_proof_v2_vkey.json
```

Announce the **beacon** before the ceremony starts: for example the drand
round, or the Bitcoin block height, whose value will be used. The last
contributor then cannot choose it.

## Publication

For each circuit, publish:

- the frozen `.circom` hashes and circom version;
- the `.r1cs` hash;
- the phase 1 file hash;
- every intermediate `.zkey` hash;
- contributor names, attestations and contribution hashes;
- the beacon value;
- the final `.zkey`, `vkey.json` and wasm.

Anyone can then re-run `snarkjs zkey verify`. Pin the final artifacts' SHA-256
in `zkp/artifact-manifest.json` with a production `circuitId`. mubEZ already
refuses artifacts whose digest does not match.

## Readiness checklist

- [ ] Audit report received, findings fixed and re-reviewed
- [ ] Circuits frozen (hashes recorded), production depth confirmed (20)
- [ ] Phase 1 file chosen, downloaded and hash-verified
- [ ] ≥ 5 contributors confirmed, with dates
- [ ] Beacon source and round/height announced
- [ ] Coordinator runbook rehearsed on the development circuits
- [ ] Transcript location chosen (public repository or site)
