# sapio_tee

Run [Sapio](https://github.com/stutxo/sapio)'s full **ProgramOracle** inside an **AWS Nitro Enclave**, with deterministic key recovery through attested AWS KMS operations.

The signer evaluates bounded inline WASM predicates (v1 and v2) and a fixed, measured `pay-at-least/v1` interpreter. Clients verify the enclave's public identity, including its program capabilities, pin its extended public key, and sign explicit `ProgramSigningRequest`s using Sapio's `ProgramClient`.

“Program” here means a signing predicate implementing Sapio's evaluator ABI,
not an arbitrary Sapio compiler-plugin WASM module. Compile contracts and plan
transactions on the client; send their supported program instances and spend
requests to the enclave. Custom inline predicates need no enclave rebuild.
See the “Program compatibility and authoring” section in [USAGE.txt](USAGE.txt).

> **Status:** a live Nitro boot, attested KMS provisioning, client attestation verification, program signing, and service-restart recovery **have now been exercised once** on a signet test deployment; see [verification evidence](VERIFICATION.txt). That is one operator run — not third-party reproduction, soak evidence, or a production-custody assurance. Review the [security model](SECURITY.txt).

## How it works

1. The parent EC2 instance runs the pinned `enclaver` supervisor and relays connections over vsock. The signer runs inside the enclave.
2. Production startup requires Nitro's Security Module (`/dev/nsm`) and locked, nonzero PCR0, PCR1, and PCR2. Debug enclaves are rejected.
3. A one-time setup supplies a full KMS key ARN, an agreed Bitcoin blockhash, and a Bitcoin network. The enclave derives a P-256 NUMS public point from the blockhash.
4. The enclave-local KMS proxy attaches recipient attestation to an ECDH `DeriveSharedSecret` request. KMS returns the secret encrypted to an enclave-held recipient key; the proxy unwraps it inside the enclave.
5. Settings-bound HKDF produces a BIP32 seed for the Sapio oracle. The same KMS key material, exact ARN, blockhash, network, and derivation version recover the same root. No seed import, export, or persistent enclave disk is required.
6. A client challenges the enclave with a fresh nonce. The attestation binds the exact public identity, including xpub, setup settings, and signing profile; the supplied verifier checks the certificate chain, signature, measurements, nonce, freshness, identity binding, and independently expected profile.

The design follows [confidential-script-tee](https://github.com/joshdoman/confidential-script-tee), using a pinned [nix-enclaver](https://github.com/joshdoman/nix-enclaver) supervisor and the existing Sapio signer rather than Confidential Script's signing engine.

## Local quick start

Use an **x86_64 Linux** workstation with [Nix](https://nixos.org/download/) installed and the `nix-command` and `flakes` features enabled. The development shell supplies the pinned Rust 1.98.1 toolchain and native dependencies. The enclave image itself targets **aarch64** (Graviton Nitro Enclaves) and is cross-compiled from this x86_64 host.

From the repository root:

```sh
nix develop --no-update-lock-file -c cargo run --locked --features local-dev -- --local-dev
```

In another terminal:

```sh
curl --fail http://127.0.0.1:8000/health
curl --fail http://127.0.0.1:8000/public-key > local-identity.json
nix develop --no-update-lock-file -c cargo run --locked --example program_oracle -- \
  --address 127.0.0.1:8367 --identity local-identity.json --allow-local-dev
```

The example uses synthetic funding and does not broadcast transactions. `ProgramClient` checks returned signatures and PSBT integrity against the pinned root. Port 8367 speaks length-prefixed `SignProgramV1` JSON over TCP, **not HTTP**.

Local mode generates an ephemeral **regtest** root, never calls AWS, and cannot produce attestation. Its identity reports `mode: "local-dev"` and `settings: null`. The root changes on restart; do not use it for funds. Local mode requires both the compile-time feature and the explicit CLI flag, and is excluded from the EIF build.

Arbitrary predicates within Sapio's inline WASM ABI and resource limits can be sent without adding an interpreter to the registry. Adding or changing a **registered** evaluator instead requires a code/image rebuild, independently reviewed new PCRs, a KMS-policy update, and a newly trusted expected profile. The built-in registry is not a runtime upload API.

### Example: a flexible payment rule

[`examples/program_oracle.rs`](examples/program_oracle.rs) runs against the real TCP signer. Its registered `pay-at-least/v1` program commits to **at least 9,000 sats to a fixed recipient**, not a single transaction template:

| Candidate spend | Result |
| --- | --- |
| Pay 9,000 sats to the recipient at output 0 | Signature accepted |
| Pay 11,000 sats to the same recipient at output 1 | Signature accepted |
| Pay 8,999 sats | Rejected |
| Redirect the payment to another recipient | Rejected |
| Substitute different committed program parameters | Rejected |

The two accepted transactions are alternatives spending the **same funding output under the same program commitment**. Only the transaction and its output-index witness change. `ProgramClient` verifies the returned signatures and checks that unrelated PSBT fields were preserved.

The example also exercises authenticated script-path signing, a nonzero selected input, inline CTV, a WASM v2 lock-time predicate, traps, fuel exhaustion, and successful signing after rejected requests. Run it with the two-terminal quick start above; it prints a `PASS` line for each observed behavior and exits nonzero on failure. Funding is synthetic: nothing is broadcast and no AWS credentials are needed for local mode.

### Example: BIP-446 OP_TEMPLATEHASH emulation

[`examples/templatehash`](examples/templatehash) emulates the proposed
`OP_TEMPLATEHASH` soft-fork opcode with an inline v1 predicate: the committed
program is a 32-byte template hash, and the oracle signs only the exact
transaction that reproduces it (sequences and outputs committed; prevouts
deliberately free, so other inputs may be rebound). The client example
cross-checks its hash assembly against rust-bitcoin's own BIP341 sighash —
including on a transaction from the official BIP-446 test vectors — then
exercises acceptance, every committed-field mutation, and rebind acceptance
against the live oracle. See [provenance and encoding](examples/templatehash/PROVENANCE.txt).

### Example: a source-built withdrawal vault

The [`vault` example](examples/vault/main.rs) shows the full path from a Rust
predicate to a compiled Sapio contract and a remotely signed, finalized PSBT:

- [`predicate.rs`](examples/vault/predicate.rs): the Rust code compiled to inline
  WASM. It requires one input, one output at or above the 330-satoshi dust
  floor, the committed destination, and a fee no greater than the committed cap.
- [`contract.rs`](examples/vault/contract.rs): the small `#[sapio::contract]`
  wrapper that commits the WASM and parameters through `EmulatedProgram`.
- [`main.rs`](examples/vault/main.rs): client-side compilation, synthetic funding,
  `prepare_program_request`, `ProgramClient`, and Miniscript finalization.

With the local signer and identity from the quick start:

```sh
nix develop --no-update-lock-file -c cargo run --locked --example vault -- \
  --address 127.0.0.1:8367 --identity local-identity.json --allow-local-dev
```

It accepts 500-sat and 1,000-sat fees, rejects excessive fees, redirection,
extra inputs/outputs, sub-dust sweep outputs, unexpected evidence and policy
substitution, then signs a valid sweep again. The same program commitment and funding are retained for
the predicate comparisons. Nothing is broadcast.

**This is a permissionless fixed-recipient sweep, not a recovery vault.**
Anyone can trigger an allowed withdrawal. There is no owner authorization,
timelock, recovery path, change output or partial withdrawal. Do not fund the
disposable example addresses.

The checked-in `vault.wasm` lets the client run without rebuilding the guest.
To verify its source/artifact correspondence:

```sh
nix develop --no-update-lock-file -c bash examples/vault/build.sh --check
```

After deliberately editing the predicate, use `--write` to rebuild the artifact.
Changing its bytes or parameters changes the program-derived key; it does not
update an already funded contract. See [provenance and encoding](examples/vault/PROVENANCE.txt).
CI checks the exact WASM bytes and runs both signing examples. This inline
program needs no registry change or enclave redeployment.

### Experiment: generic Groth16 proof core

[`generic-guest`](experiments/op_checkzkp/generic-guest/src/lib.rs) is a reusable
BN254 Groth16 verifier using unchanged arkworks 0.5 arithmetic. Its native/rlib
API is `verify(verifying_key, proof, public_inputs) -> Result<bool, VerifyError>`.
It has **no built-in SHA-secret relation, transaction digest, or authorization
policy**. The calling application must authenticate/commit the reviewed verifier
and verification key, select the intended circuit/setup, and derive the correct
transaction-bound public inputs. Proof validity alone is not permission to sign.

Arguments are exact arkworks 0.5 `CanonicalSerialize` **uncompressed** encodings
of `VerifyingKey<Bn254>`, `Proof<Bn254>`, and `Vec<Fr>`. Each buffer is bounded by
65,536 bytes. Counts are checked against actual payload lengths before any
vector allocation; decoding rejects trailing bytes, noncanonical scalars, and
invalid curve/subgroup points. A streaming canonical-serialization comparison
also rejects point sign/infinity aliases that `Deserialize` alone accepts.
Canonical identity points remain valid, including identity IC coefficients.
Public scalars use the full field, not the demo's 128-bit digest halves.

For `n` public inputs, the key is `520 + 64*n` bytes, the proof is 256 bytes,
and the input vector is `8 + 32*n` bytes, with upstream little-endian `u64`
sequence lengths. Zero public inputs still require the eight-byte zero count
and one IC point. The key byte cap permits at most 1,015 inputs; this is a
serialization bound, **not** a promise that every such key fits a fuel budget.
This is not a `G16M`, `G16A`, or `G16L` prepared-key format.

The WASM exports only `memory`, `groth16_alloc_v1(len) -> ptr`, and
`groth16_verify_v1(vk_ptr, vk_len, proof_ptr, proof_len, inputs_ptr, inputs_len)`.
Pointers/lengths are `u32`; verification returns 1 for valid, 0 for a false
equation, and -1 for malformed input/verifier error. Allocation failure, traps,
and fuel exhaustion are execution errors, never proof rejections. There are
no imports, start function, or `sapio_*` signing entrypoints.

With the pinned dependencies cached:

```sh
bash experiments/op_checkzkp/build-generic.sh
experiments/op_checkzkp/target/release/checkzkp-generic-probe --benchmark \
  experiments/op_checkzkp/target/generic-comparison/groth16.wasm \
  experiments/op_checkzkp/fixtures/generic-corpus.json \
  --legacy-diagnostic --diagnostic-fuel 1000000000
```

The checked-in [public corpus](experiments/op_checkzkp/fixtures/generic-corpus.json)
and [measured results](experiments/op_checkzkp/fixtures/generic-results.json)
preserve the exact benchmark below; no fresh setup is needed to replay it.

`--generate-corpus PATH` creates additional public fixtures without overwriting
existing files. Fixtures use real official setup/proving for 0/1/6/32-input
algebraic workloads, not an authorization policy;
no proving keys or secrets are written. Unused R1CS inputs retain the official
reduction. Separately named, algebraically constructed identity-IC fixtures
test verifier semantics without claiming a production setup. Native checking
uses the **same arithmetic library**, not an independent cryptographic reference.
For external proofs, `--verify MODULE VK_FILE PROOF_FILE PUBLIC_INPUTS_FILE`
takes raw binary files and executes WASM directly; use the same diagnostic flags
for this oversized artifact. False/malformed results exit unsuccessfully.

**Cold-path measurement:** every fresh WASM call performs canonical decoding,
key/point validation, key preparation, MSM, and official Groth16 verification.
There are no native prepared tables, folded application constants, or cached-key
discounts. The optimized module is **107,252 bytes**; observed linear memory is
8 MiB, with a declared 64 MiB maximum and a bounded 4 MiB heap.

| Valid workload | Public inputs | Measured full-path fuel |
| --- | ---: | ---: |
| Algebraic relation | 0 | 165,301,843 |
| Constrained full-field scalar | 1 | 168,010,746 |
| Algebraic relation | 6 | 198,621,592 |
| Algebraic relation | 32 | 339,724,827 |

All **37 cases** (13 full verifications, 24 malformed inputs) and **28 valid
replays** pass with the explicit 1B diagnostic allowance. The largest full-case
cost is **339,768,557 fuel**, including false proofs. A separate maximum-size
identity-IC key (65,480 bytes, 1,015 inputs) also verifies at 8 MiB; that algebraic
boundary check is not worst-case arithmetic. Direct ABI checks cover pointer,
allocation, replay, and input-length boundaries.
Module SHA256: `600bef7179f2cf8b5ad6f4faa2ab86db8213c568d0ad8fc0240b3c7692a97c6f`.
Corpus SHA256: `52a12bb5a5015da9e0567badca6ce58b498f2cbeb2363ce0de3961e20c8dd75c`.
Fuel values describe this public sample, not a universal bound or Nitro timing.

**This cold generic implementation exceeds both current production limits.**
The actual pinned Sapio evaluator rejects its size; all full corpus cases
exhaust the unchanged 100M allowance when only size admission is waived.
The prepared SHA-demo's code-size-only admission issue below does not apply to
this interface. No limits changed, no generic oracle signature was requested,
and no funds were used. The original frozen corpus/control remains unchanged
at 63,683 bytes and 65,786,641 maximum fuel.

### Experiment: pure-WASM Groth16 authorization

[`experiments/op_checkzkp`](experiments/op_checkzkp) verifies a BN254 Groth16
proof of knowledge of a 32-byte secret `s`, with `C = SHA256(s)` and
`A = SHA256(s || T)`. The guest recomputes
`T = SHA256("sapio/checkzkp/bn254/v1" || SHA256(encoded_signed_view))`.
Only the existing SHA256 host import is used; proof validation and all per-spend
ZKP arithmetic execute in WASM. The retained `substrate-bn` backend has an
independent arkworks reference.
These SHA-secret application backends remain comparison controls, not generic
verifier resource measurements; they prepare the key and fold the fixed
commitment before metered verification.

From the repository root, with the pinned dependencies already cached:

```sh
bash autoresearch.sh
nix develop --offline --no-update-lock-file --command env RAYON_NUM_THREADS=1 \
  experiments/op_checkzkp/target/release/checkzkp-probe \
  experiments/op_checkzkp/target/checkzkp_guest.scored.wasm
```

The first command builds offline and measures the frozen public corpus. Its
diagnostic allowance is not a deployment gate. The second generates a fresh
private setup and proof, invokes the actual unchanged `ProgramOracle`, validates
the returned signature with `validate_program_response`, and checks rejection of
an invalid proof and changed transaction under the original 100,000,000 fuel cap.
Both commands are local-only; funding is synthetic and nothing is broadcast.

After 50 experiments, the frozen full-path maximum is **65,786,641 fuel**,
down from 488,320,714 (86.5%). The scored module is 63,683 bytes against the
unchanged 65,536-byte cap; parameters are 34,149 bytes, the witness is 288 bytes,
and linear memory is 8 MiB against the unchanged 64 MiB cap. Fresh synthetic
requests also pass the actual production signing and response-validation gate.

**Preparation is a security boundary.** The retained backend's producer in
[`probe/src/prepared.rs`](experiments/op_checkzkp/probe/src/prepared.rs) validates
every original key point before computing the constant pairing, fixed G2 lines,
and fixed commitment contribution. Canonical prepared decoding does not
authenticate arbitrary tables. Use this validated producer before deriving the
funding address; the complete module and prepared parameters determine a new
program identity, not an upgrade of existing funded outputs.

The prepared format is `G16M || pairing[33792] || folded_IC[65] ||
IC3..IC6[256] || C[32]`, totaling 34,149 bytes. Each pairing-field value `x` is
encoded as the canonical Montgomery residue `x * 2^256 mod q` in 32 big-endian
bytes; decoding still rejects every residue at or above `q`. This avoids
repeating field conversions during each spend. The previous `G16C` tag is not
accepted. Source-key, proof, and IC point coordinates retain their ordinary
canonical encoding. Only the computed folded IC may encode infinity: tag zero
with 64 zero bytes; finite points use tag one and canonical coordinates.
Original source and proof points still forbid infinity.
All 43 frozen outcomes are checked independently with arkworks: 29 execute in
WASM, and 14 malformed source-key cases are rejected during preparation, never
counted as guest rejections. All 14 full-path cases reach WASM, followed by a
valid replay in a fresh instance.
The corpus maximum is not a universal worst-case bound. This remains an
experimental single-party setup, not audited custody software or a Nitro
performance measurement; never fund its disposable keys.

#### Arkworks backend comparison

```sh
bash experiments/op_checkzkp/compare-arkworks.sh
```

This separately builds `ark-groth16` / `ark-bn254` 0.5.0 in pure WASM, using
the same pinned compiler, Binaryen pass, frozen corpus, fixed-key preparation
and commitment folding. The standard variant calls the official Groth16
verifier; the `msm` variant uses arkworks' variable-base MSM before its verifier.
Neither changes the relation or production limits. Outputs and full logs are
under `experiments/op_checkzkp/target/arkworks-comparison/`; the retained scored
artifact and autoresearch history are not overwritten.

| Backend | Frozen full-path maximum fuel | Module bytes | Production admission |
| --- | ---: | ---: | --- |
| Retained `substrate-bn` | 65,786,641 | 63,683 | Pass, including actual signing |
| Arkworks standard | 88,371,004 | 91,610 | Reject: module exceeds 65,536 bytes |
| Arkworks MSM | 85,616,636 | 96,372 | Reject: module exceeds 65,536 bytes |

All three pass the same 43 corpus outcomes and valid replay. Arkworks consumes
34.3% more fuel, or 30.1% more with MSM, in this configuration. Its `G16A`
parameters are 34,597 bytes: the extra 448 bytes retain real fixed VK metadata
for the official API. The validated producer is in
[`ark-guest/src/lib.rs`](experiments/op_checkzkp/ark-guest/src/lib.rs).
Prepared tables use arkworks' own coefficient ordering and are not `G16M`.
Native arkworks is not an independent arithmetic reference for arkworks WASM;
the retained substrate backend supplies the cross-backend comparison.

The runner explicitly enables `--backend arkworks --legacy-diagnostic` to
measure oversized modules; this is not production admission or permission to
sign. Fresh production invocations without diagnostic flags were rejected by
the actual evaluator's byte cap. Fresh diagnostic proofs also passed with
100,000,000 fuel, but no arkworks oracle signatures were requested. The corpus
maximum remains a sample, not a universal bound; the retained backend remains
a frozen, resource-compliant comparison control, not a custody recommendation.

#### Upstream-only MCL comparison

[`build-mcl.sh`](experiments/op_checkzkp/build-mcl.sh) pins MCL v4.10 at
`cbb18eb08b86129cf936a6436b5e6c68a2ce8ddf`, verifies the source archive SHA256,
and builds unchanged upstream arithmetic for `BN_SNARK1` with
`MCL_FP_BIT=256` / `MCL_FR_BIT=256`. The small adapter owns only the ABI,
canonical codecs, validation, transaction binding and ordinary Groth16 equation.
No fork arithmetic, production limits, funded outputs or autoresearch artifacts
are changed.

```sh
# Explicit source download; subsequent builds are offline.
bash experiments/op_checkzkp/build-mcl.sh fetch
bash experiments/op_checkzkp/build-mcl.sh build Oz cpp
nix develop --offline --no-update-lock-file --command \
  env CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 RUSTFLAGS= \
  cargo build --offline --locked --manifest-path experiments/op_checkzkp/Cargo.toml \
  -p checkzkp-probe --release --target-dir experiments/op_checkzkp/target
experiments/op_checkzkp/target/release/checkzkp-probe --benchmark \
  experiments/op_checkzkp/target/mcl-comparison/mcl.wasm \
  experiments/op_checkzkp/fixtures/corpus.json --backend mcl --legacy-diagnostic
```

The builder accepts `Oz|Os` and `cpp|llvm`; `llvm` selects upstream's existing
`MCL_USE_LLVM=1`, `base32.ll` and `bint32.ll`, without generating or editing
arithmetic. Both use standalone C++03, clang 21.1.8, bundled rust-lld 22.1.8,
LTO and Binaryen 132. Outputs, including the native `prepare` executable and
upstream copyright notice, stay under `target/mcl-comparison/`. The default
`cpp -Oz` module rebuilt byte-identically after a fresh verified source download.

| MCL configuration | Frozen full-path maximum fuel | Module bytes |
| --- | ---: | ---: |
| C++ `-Oz` (default, smallest) | 504,466,761 | 137,850 |
| C++ `-Os` | 454,012,024 | 152,156 |
| Upstream LLVM `-Oz` | 460,487,877 | 188,502 |
| Upstream LLVM `-Os` (fastest) | 422,534,289 | 199,610 |

All four pass all 43 frozen outcomes and fresh-instance replay against the
independent native arkworks reference: 14 malformed source keys are rejected
during preparation, while 29 cases, including all 14 full paths, reach WASM.
Each also passes 32 direct ABI/codec smoke checks. The default additionally
passes two auxiliary valid algebraic cases covering folded/final IC infinity;
these do not change the frozen corpus. Original source/proof infinity remains
forbidden, and G2 subgroup checks remain enabled.

`G16L` parameters are 34,153 bytes: tag, little-endian coefficient count (87),
MCL's canonical Fp12 target and Fp6 gamma/delta line serializations, tagged folded
IC, four ordinary affine IC bases, and commitment. The native 64-bit producer
and WASM 32-bit consumer do not share internal limbs or reinterpret `G16M`/`G16A`.
All original VK points are validated before folding. As with the other prepared
formats, canonical decoding does not authenticate tables against a VK: validated
preparation and setup must precede funding commitment. Witnesses remain 288 bytes.

Every build uses 8 MiB observed linear memory with a configured 64 MiB ceiling,
has no start section, and exports only memory and the two guest entrypoints.
Its sole import is `sapio_crypto_v1::sha256`; initialization and all spend-time
group/pairing arithmetic are metered inside WASM. The corpus measurements use
the explicitly diagnostic 1,000,000,000-fuel allowance, not the production cap.
Actual production admission rejects the default module at 65,536 bytes.
A fresh 100,000,000-fuel diagnostic exhausts its allowance; a fresh
1,000,000,000-fuel diagnostic passes valid proof, invalid proof, changed
transaction, malformed input and replay gates. No MCL oracle signature was
requested; no funding, broadcasting, deployment or Nitro measurement occurred.

**Decision: do not promote MCL under the unchanged limits.** Even the smallest
and fastest measured configurations exceed their respective caps. Stock
arkworks standard remains the measured unmodified alternative that fits fuel,
but needs explicit authorization for a module cap of at least 91,610 bytes.
No cap increase or return to private arithmetic rewrites is part of this result.

MCL is established upstream software, not an audit certificate for this adapter.
[Quarkslab's qualified 2020 assessment](https://blog.quarkslab.com/technical-assessment-of-the-herumi-libraries.html)
covered older MCL v1.23, principally BLS12-381; it does not establish assurance
for this exact BN_SNARK1/WASM configuration. The new adapter remains unaudited.

## Build the Nitro image

```sh
nix flake check --no-update-lock-file --no-build
nix build --no-update-lock-file .#eif --out-link result-eif
nix build --no-update-lock-file .#enclaver --out-link result-runner
```

| Output | Purpose |
| --- | --- |
| `result-eif/sapio_tee.eif` | Deployable aarch64 enclave image (Graviton Nitro Enclaves) |
| `result-eif/pcr.json` | Measurements emitted by the image builder |
| `result-runner/bin/enclaver` | Parent-side runner and proxies |

The build includes the musl signer, supervisor, init, and Linux kernel; the first build can be substantial. Inputs are locked, but **pinning alone does not prove reproducibility**. Independently rebuild and compare the image and measurements before trusting them. The pinned ARM parent runner is statically linked and can be copied directly; Nix is only needed on the build machine.

## Deploy and establish trust

For a single-box test deployment, [`deploy/terraform`](deploy/terraform) builds
the locked EIF/runner locally, uploads them to a private S3 bucket, creates a
PCR-bound KMS key and Graviton `m7g.xlarge`, starts the enclave under systemd,
initializes it, and waits for a successful per-instance Systems Manager readiness
check. Configure the inputs, run `terraform init`, then `terraform apply`:
no manual build/upload/SSH launch is needed. SSH remains operator-only.
See the [one-apply workflow in USAGE.txt](USAGE.txt), including the KMS
`prevent_destroy` guard. The supplied regtest block hash is a public test fixture;
automatic setup does not satisfy the future-block custody procedure below, and
the test configuration refuses `network = "bitcoin"` outright.

Follow the complete [build, provisioning, attestation, and recovery guide](USAGE.txt). Deployment requires:

- An enclave-enabled aarch64 (Graviton) EC2 parent with `nitro-cli`, the Nitro driver, and the allocator service configured.
- An AWS-generated **`ECC_NIST_P256` / `KEY_AGREEMENT`** KMS key, an instance-profile role, and a separate administrator role in the same commercial AWS account.
- An independently reviewed PCR0 policy generated with [`deploy/key-policy.py`](deploy/key-policy.py).
- A future, unpredictable Bitcoin blockhash agreed upon **after** restricting and auditing the KMS policy; verify its provenance and confirmation depth independently.
- Restricted parent ingress on ports **8000 and 8367** before launch. The upstream runner binds all IPv4 interfaces.

For a manual deployment, start the enclave using [`deploy/run-enclave.py`](deploy/run-enclave.py) and initialize it once. Both workflows still require verification using [`scripts/verify-attestation.py`](scripts/verify-attestation.py) with an independently trusted AWS root certificate, expected setup settings, expected program profile, fresh challenge, and independently reproduced PCR0/1/2. Generate the profile offline from your independently reviewed application build:

```sh
./result-app/bin/sapio-tee --program-profile > expected-program-profile.json
```

Build `result-app` with `nix build --no-update-lock-file .#app --out-link result-app` first. The binary is aarch64: run this step on an aarch64 Linux host (e.g. the parent, or with qemu-user binfmt on the build machine). The command requires no NSM or AWS access. Pass `--program-profile expected-program-profile.json` to the verifier; never extract your expected profile from the host's response. Production clients consume `verified-identity.json` and omit `--allow-local-dev`:

```sh
nix develop --no-update-lock-file -c cargo run --locked --example program_oracle -- \
  --address 127.0.0.1:8367 --identity verified-identity.json
```

**Do not trust `/public-key` by itself.** Only an explicit Terraform apply provisions AWS resources; the policy generator and launcher do not.

### API

The HTTP API listens on enclave loopback port 8000; the parent forwards it.

| Endpoint | Behavior |
| --- | --- |
| `GET /health` | `200` once initialized; `503` before setup |
| `POST /setup` | Initialize once with `key_id`, `blockhash`, and `network`; repeated setup returns `409` |
| `GET /public-key` | Return `protocol`, `mode`, `xpub`, `settings`, and the `signing` profile |
| `POST /attestation` | Accept a hex nonce of 16–64 bytes; return the NSM document and its bound `identity_json` |

The ProgramOracle TCP signer starts on port 8367 only after successful initialization. Its public identity protocol is `sapio-tee/program-oracle/1`. The profile binds `SignProgramV1`, inline v1/v2, the exact registered interpreter ID, four admitted connections, and a 30-second request I/O timeout. This is not a hard CPU deadline for native WASM compilation. See [USAGE.txt](USAGE.txt) for the full profile, `ProgramSigningRequest` shape, and commands.

## Security boundaries

- **Key custody, not transaction confidentiality:** programs, parameters, witnesses, PSBTs, and API traffic remain visible to the parent. There is no attested TLS channel or application authentication.
- **Attestation is not a session binding:** clients must pin the verified xpub and validate signing responses. A malicious parent can relay a genuine enclave's attestation or deny service.
- **The KMS administrator remains trusted:** the supplied policy can be changed by its administrator. The application does not prove policy immutability or historical exclusive key custody.
- **Recovery depends on KMS:** preserve the exact public setup record, verified xpub, source/locks, image, measurements, and policy history. Losing the KMS key or its authorization can strand funds. Changing the ARN, including switching to a multi-region replica ARN, changes the root.

Read [SECURITY.txt](SECURITY.txt) before deployment or funding contracts.

## Verification

```sh
nix develop --no-update-lock-file -c cargo test --locked --no-default-features
nix develop --no-update-lock-file -c cargo test --locked --features local-dev
nix develop --no-update-lock-file -c cargo clippy --locked --all-targets --all-features -- -D warnings
nix develop --no-update-lock-file -c python3 -m unittest discover -s tests -p 'test_*.py'
```

The software checks cover program signing and signed X509/COSE attestation fixtures, including genuine but unexpected program identities. Test certificates are **not** Nitro hardware evidence. Consult [VERIFICATION.txt](VERIFICATION.txt) for the commands actually exercised, their results, and the untested hardware boundary.

## Documentation and license

- [Operations and recovery](USAGE.txt)
- [Security model and limitations](SECURITY.txt)
- [Verification evidence](VERIFICATION.txt)
- [Changelog](CHANGELOG.txt)

Licensed under [MPL-2.0](LICENSE). Dependency licenses remain their respective owners'.
