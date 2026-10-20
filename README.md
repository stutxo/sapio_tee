# sapio_tee

Run upstream [Sapio](https://github.com/sapio-lang/sapio)'s full **ProgramOracle** inside an **AWS Nitro Enclave**, with deterministic key recovery through attested AWS KMS operations.

The signer evaluates bounded inline WASM predicates (v1 and v2) and a fixed, measured `pay-at-least/v1` interpreter. Clients verify the enclave's public identity, including its program capabilities, pin its extended public key, and sign explicit `ProgramSigningRequest`s using Sapio's `ProgramClient`.

“Program” here means a signing predicate implementing Sapio's evaluator ABI,
not an arbitrary Sapio compiler-plugin WASM module. Compile contracts and plan
transactions on the client; send their supported program instances and spend
requests to the enclave. Custom inline predicates need no enclave rebuild.
See the “Program compatibility and authoring” section in [USAGE.txt](USAGE.txt).

> **Status:** a live Nitro boot, attested KMS provisioning, client attestation verification, program signing, and service-restart recovery **have now been exercised once** on a signet test deployment; see [verification evidence](VERIFICATION.txt). That is one operator run — not third-party reproduction, soak evidence, or a production-custody assurance. Review the [security model](SECURITY.txt).

This standalone repository pins unmodified `sapio-lang/sapio` at
`c8f4e63123e724dc1144075af8ac0dbd3cf4e0b1` and the public
[`stutxo/saplingos`](https://github.com/stutxo/saplingos) Ark library at an exact
revision in `Cargo.toml` and `Cargo.lock`. No sibling checkout or Sapio fork is
required. Historical deployment evidence does not establish verification of a
new image; independently rebuild and verify its measurements.

## How it works

1. The parent EC2 instance runs the pinned `enclaver` supervisor and relays connections over vsock. The signer runs inside the enclave.
2. Production startup requires Nitro's Security Module (`/dev/nsm`) and locked, nonzero PCR0, PCR1, and PCR2. Debug enclaves are rejected.
3. A one-time setup supplies a full KMS key ARN, an agreed Bitcoin blockhash, and a Bitcoin network. The enclave derives a P-256 NUMS public point from the blockhash.
4. The enclave-local KMS proxy attaches recipient attestation to an ECDH `DeriveSharedSecret` request. KMS returns the secret encrypted to an enclave-held recipient key; the proxy unwraps it inside the enclave.
5. Settings-bound HKDF produces a BIP32 seed for the Sapio oracle. The same KMS key material, exact ARN, blockhash, network, and derivation version recover the same root. No seed import, export, or persistent enclave disk is required.
6. A client challenges the enclave with a fresh nonce. The attestation binds the exact public identity, including xpub, setup settings, and signing profile; the supplied verifier checks the certificate chain, signature, measurements, nonce, freshness, identity binding, and independently expected profile.
7. Ark nested signing authenticates the original spend and its exact DEFAULT
   signature hash, evaluates the exact committed Sapio program, then permits
   the TEE-held share S to participate in C = sorted KeyAgg(U, S). The bounded
   evaluator adapter lives in this repository and uses upstream Sapio's WASM
   host and program metadata; no patched Sapio API or rewritten transaction is
   needed. Inline v1/v2 and the fixed registry run in the same enclave as S.
   Native Ark policy remains C+A, with no native-key fallback, raw-digest
   signing, or recovery exemption.
   Ark requests reject annexes because their native signing context is annex-free;
   the ordinary Sapio ProgramOracle retains upstream v2 annex support.

The design follows [confidential-script-tee](https://github.com/joshdoman/confidential-script-tee), using a pinned [nix-enclaver](https://github.com/joshdoman/nix-enclaver) supervisor and the existing Sapio signer rather than Confidential Script's signing engine.

## Local quick start

Use an **x86_64 Linux** workstation with [Nix](https://nixos.org/download/) installed and the `nix-command` and `flakes` features enabled. The development shell supplies the pinned Rust 1.98.1 toolchain and native dependencies. The enclave image itself targets **aarch64** (Graviton Nitro Enclaves) and is cross-compiled from this x86_64 host.

For a fresh public checkout containing no private changes or operational data:

```sh
git clone https://github.com/stutxo/sapio_tee.git
cd sapio_tee
export TEE_FLAKE=.
nix develop --no-update-lock-file "$TEE_FLAKE" -c cargo run --locked --features local-dev -- --local-dev
```

For a live/private worktree, first complete the plan, positive content review,
and snapshot steps in the [Build section of USAGE.txt](USAGE.txt). Nix copies
`path:` inputs into its world-readable store before any source filter runs;
this includes the TEE flake itself. Never give Nix a raw private worktree.
Run native Cargo commands from the original worktree, not the read-only
snapshot. Repeat this setup in each terminal instead of `TEE_FLAKE=.`:

```sh
export TEE_SOURCE="$SOURCE_SNAPSHOT/sapio_tee"
python3 scripts/source_snapshot.py verify "$TEE_SOURCE"
export TEE_FLAKE="path:$TEE_SOURCE"
nix develop --no-update-lock-file "$TEE_FLAKE" -c cargo run --locked --features local-dev -- --local-dev
```

In another terminal:

```sh
curl --fail http://127.0.0.1:8000/health
curl --fail http://127.0.0.1:8000/public-key > local-identity.json
nix develop --no-update-lock-file "$TEE_FLAKE" -c cargo run --locked --example program_oracle -- \
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
nix develop --no-update-lock-file "$TEE_FLAKE" -c cargo run --locked --example vault -- \
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
nix develop --no-update-lock-file "$TEE_FLAKE" -c bash examples/vault/build.sh --check
```

After deliberately editing the predicate, use `--write` to rebuild the artifact.
Changing its bytes or parameters changes the program-derived key; it does not
update an already funded contract. See [provenance and encoding](examples/vault/PROVENANCE.txt).
CI runs the same locked checks from a standalone public checkout. This inline
program needs no registry change or enclave redeployment.

## Build the Nitro image

```sh
nix flake check --no-update-lock-file "$TEE_FLAKE" --no-build
nix build --no-update-lock-file "$TEE_FLAKE#eif" --out-link result-eif
nix build --no-update-lock-file "$TEE_FLAKE#enclaver" --out-link result-runner
```

| Output | Purpose |
| --- | --- |
| `result-eif/sapio_tee.eif` | Deployable aarch64 enclave image (Graviton Nitro Enclaves) |
| `result-eif/pcr.json` | Measurements emitted by the image builder |
| `result-runner/bin/enclaver` | Parent-side runner and proxies |

The build includes the musl signer, supervisor, init, and Linux kernel; the first build can be substantial. Retain the exact public source revision (or reviewed snapshot) and both lock files. All dependencies use public locked sources; **pinning alone does not prove reproducibility**. Independently rebuild and compare the image and measurements before trusting them. The pinned ARM parent runner is statically linked and can be copied directly; Nix is only needed on the build machine. To build only the application, select `#app`; that does not assemble an EIF.

## Deploy and establish trust

For a single-box test deployment, [`deploy/terraform`](deploy/terraform) builds
EIF/runner locally from the reviewed source snapshot, uploads them to a private S3 bucket, creates a
PCR-bound KMS key and Graviton `m7g.xlarge`, starts the enclave under systemd,
initializes it, and waits for a successful per-instance Systems Manager readiness
check. Export `TEE_SOURCE` to the reviewed code-only TEE snapshot. The build
script checks its inventory before each Nix import; it never imports the
operational Terraform worktree. Dependencies come from the public lock files.
Configure the inputs, run `terraform init`, then `terraform apply`:
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

Build `result-app` with `nix build --no-update-lock-file "$TEE_FLAKE#app" --out-link result-app` first. The binary is aarch64: run this step on an aarch64 Linux host (e.g. the parent, or with qemu-user binfmt on the build machine). The command requires no NSM or AWS access. Pass `--program-profile expected-program-profile.json` to the verifier; never extract your expected profile from the host's response.

The expected profile must include `ark_signing` with protocol
`sapio-ark/nested-signing/1`, integer `max_pending_sessions: 256`, integer
`max_sessions_per_user: 8`, integer `session_lifetime_secs: 120`, and
`native_ownership_policy: true`. The verifier rejects missing or extra fields,
false capability flags,
different protocols, and different limits. The example identity loader compares
the complete profile to its own reviewed build, including this contract. The
contract requires both user and TEE keys, with program evaluation and the TEE key
inside the same enclave. It grants no raw-digest signing or recovery exception.
Root initialization remains a runtime operation.

Production clients consume `verified-identity.json` and omit `--allow-local-dev`:

```sh
nix develop --no-update-lock-file "$TEE_FLAKE" -c cargo run --locked --example program_oracle -- \
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
| `POST /ark/prepare` | Evaluate the exact spend and fix a one-use nested signing session to the user's nonce |
| `POST /ark/finish` | Consume the session and return the program participant's verified-context partial signature |
| `POST /ark/cancel` | Discard an unused session |

Every admitted HTTP request — header dispatch, body read and handler work — must
complete within 30 seconds. Stalled or trickled requests are answered
`408 request deadline exceeded` and release their admission slot; per-route
admission admits 16 concurrent requests and sheds excess load with `503`.
The deadline races handler work rather than cancelling it: an evaluation that
overruns keeps running server-side (native compilation is not preemptible,
same as the ProgramOracle request I/O timeout), and a session prepared after
a timed-out prepare is retained until its normal expiry.

The ProgramOracle TCP signer starts on port 8367 only after successful initialization. Its public identity protocol is `sapio-tee/program-oracle/1`. The profile binds `SignProgramV1`, inline v1/v2, the exact registered interpreter ID, four admitted connections, and a 30-second request I/O timeout. This is not a hard CPU deadline for native WASM compilation. See [USAGE.txt](USAGE.txt) for the full profile, `ProgramSigningRequest` shape, and commands.

Ark uses `C = sorted KeyAgg(U, S)`, where `S` is the exact program-instance
key derived from the verified Sapio root. Captaind still signs its native
`sorted KeyAgg(C, A)` policy. The delayed user claim requires `C`; neither
the TEE alone nor the user alone can sign it. Program evaluation and the
private `S` remain in the same process inside the enclave.

The JSON contract is defined by `ark::sapio::protocol` in the reviewed Sapling
source. Spend requests bind the actual transaction, all previous outputs,
input index, spend path, participant keys, program instance and evidence.
Fixed native ownership-proof domains are separate from Bitcoin spends.
There is no raw-digest spend endpoint or special recovery authorization.

The user nonce is fixed before the TEE nonce is returned. Finishing consumes
the nonce before validating peer data; replay, cancellation, expiry and
process restart cannot reuse it. At most 256 sessions live for 120 seconds,
and at most 8 concurrent sessions per wallet key. Wallet keys are
caller-generated, so the per-wallet cap raises the cost of exhausting the
shared pool rather than preventing it outright; deployments exposing `/ark/*`
to untrusted callers should add connection- or IP-level fairness in front.
A lost signing response needs a fresh session, not a replay of a secret nonce.
Only `/ark/*` permits credential-free browser CORS; setup and attestation do not.

Bark must durably save and independently verify its program-authorized recovery
before it hands off funding, cooperative signatures or a receive preimage.
An exact TemplateHash program can reject intermediate Ark shapes. Rejection
must stop that operation, not fall back to an unrestricted key or exemption.

### Native ownership policy and offline exits

The generic WASM evaluator sees Bitcoin spends, not the native offboard
destination or round output policies. A program that needs destination binding
for cooperative offboard/round can opt in by prefixing its parameters with
`sapio-tee/native-ownership/v1`:

```text
MAGIC || u32_le(document_len) || JSON(document) || inner_program_parameters
```

```json
{"version":1,
 "offboard":["<hex scriptPubKey>"],
 "arkoor":["<hex VtxoPolicy>"],
 "round":["<hex VtxoPolicy>"],
 "delegated_round":["<hex VtxoPolicy>"],
 "status":true,
 "lightning_receive":false}
```

Every value-moving variant is default-deny; all outputs must match an allowed
policy and offboard must match an allowed script. The envelope is part of
`ProgramInstance::id()` and the program-derived key. Only an inline WASM program
can use it, because its bytes receive the parameters; the program must ignore
the envelope or parse the trailing inner parameters. A malformed envelope fails
closed. The attested `ark_signing` profile advertises
`native_ownership_policy: true`.

This is an online cooperative-flow check. For an offline escape, the client must
also pre-sign the delayed-claim Bitcoin transaction: complete the `S` partial
with the user key locally and store the final signed tx plus its prevout. That
exit remains broadcastable with the TEE offline, but any VTXO refresh or state
change invalidates it, so create a fresh one for each state. A stored native
ownership signature is not a substitute for a stored Bitcoin exit transaction.

## Security boundaries

- **Key custody, not transaction confidentiality:** programs, parameters, witnesses, PSBTs, and API traffic remain visible to the parent. There is no attested TLS channel or application authentication.
- **Attestation is not a session binding:** clients must pin the verified xpub and validate signing responses. A malicious parent can relay a genuine enclave's attestation or deny service.
- **The KMS administrator remains trusted:** the supplied policy can be changed by its administrator. The application does not prove policy immutability or historical exclusive key custody.
- **Root-key recovery depends on KMS:** preserve the exact public setup record, verified xpub, source/locks, image, measurements, and policy history. Losing the KMS key or its authorization can strand contracts that still need signatures. Changing the ARN, including switching to a multi-region replica ARN, changes the root.
- **Prepared Bark recovery does not need a fresh root signature:** a complete saved recovery uses its existing signatures, Bitcoin chain access, mature locks and confirmed fee-wallet funds. Keep the private recovery bundle; an attested public root is not a substitute for it.

Read [SECURITY.txt](SECURITY.txt) before deployment or funding contracts.

## Verification

```sh
nix develop "${NIX_SOURCE_ARGS[@]}" "path:$TEE_SOURCE" -c cargo test --locked --no-default-features
nix develop "${NIX_SOURCE_ARGS[@]}" "path:$TEE_SOURCE" -c cargo test --locked --features local-dev
nix develop "${NIX_SOURCE_ARGS[@]}" "path:$TEE_SOURCE" -c cargo clippy --locked --all-targets --all-features -- -D warnings
nix develop "${NIX_SOURCE_ARGS[@]}" "path:$TEE_SOURCE" -c python3 -m unittest discover -s tests -p 'test_*.py'
```

The software checks cover program signing and signed X509/COSE attestation fixtures, including genuine but unexpected program identities. Test certificates are **not** Nitro hardware evidence. Consult [VERIFICATION.txt](VERIFICATION.txt) for the commands actually exercised, their results, and the untested hardware boundary.

## Documentation and license

- [Operations and recovery](USAGE.txt)
- [Security model and limitations](SECURITY.txt)
- [Verification evidence](VERIFICATION.txt)
- [Changelog](CHANGELOG.txt)

Licensed under [MPL-2.0](LICENSE). Dependency licenses remain their respective owners'.
