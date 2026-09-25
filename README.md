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

### Example: a passkey wallet with two-key recovery

[`examples/passkey`](examples/passkey) is a static
[`index.html`](examples/passkey/index.html) wallet with JavaScript and
source-built browser WASM. Visitors need a WebAuthn-capable browser, not a local
Rust server. Its Taproot address has two spending paths:

- **Normal key path:** the committed passkey authorizes the complete transaction
  before the enclave oracle signs.
- **Recovery script path:** both enrolled Bitcoin keys produce a MuSig2 signature
  for one aggregate-key `OP_CHECKSIG` leaf. Neither the passkey nor the oracle is
  needed. There is **no timelock**; either recovery key alone is insufficient.

Open the operator's **HTTPS wallet URL**. The browser builds and checks
transactions locally; normal signing sends one program-oracle request through
the EC2 parent's HTTPS-to-TCP adapter. Recovery never uses that adapter.

Deploy the web surface separately on the **existing Amazon Linux 2023 parent**.
Copy `deploy/install-web.py`, `deploy/web.py`, and the static assets from
`examples/passkey/` there, retaining their relative paths, then run:

```sh
sudo python3 deploy/install-web.py \
  --hostname wallet.example.com --assets examples/passkey \
  --identity verified-identity.json --identity-sha256 VERIFIED_FILE_SHA256 \
  --tls-cert fullchain.pem --tls-key private-key.pem
```

Supply the original independently attestation-verified public identity, its
trusted file digest, and a valid certificate/key for the stable hostname. DNS
and inbound TCP 443 must already reach this parent. The installer configures
nginx and a bounded loopback transport service; it does **not** rebuild the EIF,
run setup, replace EC2, change KMS, or rotate the root. Do not run the full
enclave deployment for a web-only update. See [USAGE.txt](USAGE.txt) for the
explicit localhost development mode and staging commands.

1. Enter **two compressed secp256k1 public keys**: 66 hex characters beginning
   with `02` or `03`. These are Bitcoin keys, not P-256 passkey keys. The pair is
   canonically sorted; repeated keys, including opposite parities, are rejected.
2. For a disposable demo, **Generate two software-demo keys** fills temporary
   public/private-key fields. Back up each private key separately before any
   signing attempt. This deliberately puts both keys in one browser: it is not
   distributed friends-and-family signing or hardware-backed custody.
3. Create the ES256 passkey and export **public metadata**. It includes the
   recovery public keys and internal key, never private keys.
4. Prepare the synthetic spend, review recipient/fee/change, and approve using
   **Passkey + enclave** or **Two-key recovery**. Recovery takes both matching
   raw 32-byte private keys in the temporary fields, in either order. It signs
   locally with source-built `libsecp256k1` MuSig2; secrets never go to the HTTPS
   adapter or oracle and are not persisted. Temporary fields clear after every
   signing attempt, cancellation, forget, or page close.
5. Download the finalized binary PSBT or transaction hex. Nothing broadcasts.

After the static assets and public config have loaded, recovery works with
**both web and oracle servers stopped and the browser offline**. Keep the
compatible static assets/config, public metadata, and separate private-key
backups. Reloading still requires serving those assets at the original origin;
this is not a `file://` wallet or an installed offline cache. There are no npm
dependencies or external scripts. Hosting integrity matters: malicious wallet
JavaScript could steal recovery keys entered into the page.

The synthetic input does not exist on-chain. Manual mode accepts one explicitly
entered UTXO and native SegWit recipients, but performs no balance, confirmation,
or prevout lookup. **This is an example, not production custody.** Do not enter
production recovery secrets into this demo. A passkey prompt is not a trusted
Bitcoin transaction display. The browser does not verify TEE attestation, and
the development software signer is not a TEE. Recovery protects availability,
**not compromise of the enclave's Bitcoin root key**. Losing either recovery
key prevents this 2-of-2 exit; public metadata cannot replace any private key.

All three checked-in WASMs work without rebuilding. To reproduce them, fetch
their standalone locked dependencies once, then build offline with the
Nix-pinned Rust 1.98.1 and Clang 21.1.8:

```sh
nix develop --no-update-lock-file -c cargo fetch --locked \
  --manifest-path examples/passkey/guest/Cargo.toml --target wasm32-unknown-unknown
nix develop --no-update-lock-file -c cargo fetch --locked \
  --manifest-path examples/passkey/recovery/Cargo.toml --target wasm32-unknown-unknown
nix develop --no-update-lock-file -c cargo fetch --locked \
  --manifest-path examples/passkey/client/Cargo.toml --target wasm32-unknown-unknown
nix develop --no-update-lock-file -c bash examples/passkey/build.sh --check
nix develop --no-update-lock-file -c cargo test --locked --example passkey
```

Use `--write` only when intentionally replacing built artifacts. Changing the
predicate, credential, recovery pair, origin, network, or root creates a
different wallet. **Existing version-1 addresses have no recovery leaf: this
does not retrofit recovery onto their funds.** Move those funds using their
original policy before adopting the new wallet. Incompatible metadata is kept
for export, never silently upgraded. See [USAGE.txt](USAGE.txt) for exact
encodings and trust boundaries. No enclave registry or signing-protocol change
is needed for this inline v2 policy.

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
