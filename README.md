# sapio_tee

Run [Sapio](https://github.com/stutxo/sapio)'s full **ProgramOracle** inside an **AWS Nitro Enclave**, with deterministic key recovery through attested AWS KMS operations.

The signer evaluates bounded inline WASM predicates (v1 and v2) and a fixed, measured `pay-at-least/v1` interpreter. Clients verify the enclave's public identity, including its program capabilities, pin its extended public key, and sign explicit `ProgramSigningRequest`s using Sapio's `ProgramClient`.

> **Status:** **Real Nitro boot, live KMS provisioning, and enclave restart/recovery have not been exercised.** Software/build results and their scope are recorded in [verification evidence](VERIFICATION.txt); this is not a production-custody assurance. Review the [security model](SECURITY.txt).

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

The build includes the musl signer, supervisor, init, and Linux kernel; the first build can be substantial. Inputs are locked, but **pinning alone does not prove reproducibility**. Independently rebuild and compare the image and measurements before trusting them. Keep the runner's Nix closure when deploying it.

## Deploy and establish trust

Follow the complete [build, provisioning, attestation, and recovery guide](USAGE.txt). Deployment requires:

- An enclave-enabled aarch64 (Graviton) EC2 parent with `nitro-cli`, the Nitro driver, and the allocator service configured.
- An AWS-generated **`ECC_NIST_P256` / `KEY_AGREEMENT`** KMS key, an instance-profile role, and a separate administrator role in the same commercial AWS account.
- An independently reviewed PCR0 policy generated with [`deploy/key-policy.py`](deploy/key-policy.py).
- A future, unpredictable Bitcoin blockhash agreed upon **after** restricting and auditing the KMS policy; verify its provenance and confirmation depth independently.
- Restricted parent ingress on ports **8000 and 8367** before launch. The upstream runner binds all IPv4 interfaces.

Start the enclave using [`deploy/run-enclave.py`](deploy/run-enclave.py), initialize it once, then verify its identity using [`scripts/verify-attestation.py`](scripts/verify-attestation.py) with an independently trusted AWS root certificate, expected setup settings, expected program profile, fresh challenge, and independently reproduced PCR0/1/2. Generate the profile offline from your independently reviewed application build:

```sh
./result-app/bin/sapio-tee --program-profile > expected-program-profile.json
```

Build `result-app` with `nix build --no-update-lock-file .#app --out-link result-app` first. The binary is aarch64: run this step on an aarch64 Linux host (e.g. the parent, or with qemu-user binfmt on the build machine). The command requires no NSM or AWS access. Pass `--program-profile expected-program-profile.json` to the verifier; never extract your expected profile from the host's response. Production clients consume `verified-identity.json` and omit `--allow-local-dev`:

```sh
nix develop --no-update-lock-file -c cargo run --locked --example program_oracle -- \
  --address 127.0.0.1:8367 --identity verified-identity.json
```

**Do not trust `/public-key` by itself.** No script in this repository creates AWS resources automatically.

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
