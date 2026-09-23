//! Public arithmetic experiment. This executable never constructs an oracle,
//! loads a key, signs a transaction, or treats a valid proof as authorization.

#[path = "../../../op_checkzkp/probe/src/runtime.rs"]
mod runtime;

use anyhow::{bail, ensure, Context, Result};
use checkstwo_prover::{check_computation, preprocessed_root, prove_computation};
use checkstwo_verifier::{
    decode_witness, encode_parameters, encode_witness, verify_bytes, Parameters, DOMAIN,
};
use runtime::{Admission, MeteredGuest};
use sapio_base::program::{MAX_PARAMETER_BYTES, MAX_PROGRAM_BYTES};
use sapio_wasm::host::INSTANCE_FUEL;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{borrow::Cow, fs, path::Path, time::Instant};

const MODULUS: u32 = 2_147_483_647;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const FIXTURES: [(&str, [u32; 2]); 3] = [
    ("small", [3, 5]),
    ("zero", [0, 0]),
    ("boundary", [MODULUS - 1, MODULUS - 2]),
];

#[derive(Serialize, Deserialize)]
struct Metadata {
    initial: [u32; 2],
    output: [u32; 2],
    preprocessed_root: [u8; 32],
    log_size: u32,
    witness_bytes: usize,
    proving_seconds: f64,
}

struct Case<'a> {
    name: &'static str,
    parameters: Cow<'a, [u8]>,
    view: Cow<'a, [u8]>,
    witness: Cow<'a, [u8]>,
    accept: bool,
}

fn context(view: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(Sha256::digest(view));
    hash.finalize().into()
}

// Same signed-view encoding consumed by the existing guest ABI. Everything is
// synthetic and public; no transaction is funded or submitted for signing.
fn synthetic_view(tag: u8) -> Vec<u8> {
    let mut view = Vec::with_capacity(86);
    view.extend_from_slice(&2u32.to_le_bytes());
    view.extend_from_slice(&0u32.to_le_bytes());
    view.extend_from_slice(&0u32.to_le_bytes()); // Selected input.
    view.extend_from_slice(&1u32.to_le_bytes());
    view.extend_from_slice(&[tag; 32]);
    view.extend_from_slice(&0u32.to_le_bytes());
    view.extend_from_slice(&u32::MAX.to_le_bytes());
    view.extend_from_slice(&100_000u64.to_le_bytes());
    view.extend_from_slice(&1u32.to_le_bytes());
    view.push(0x51);
    view.extend_from_slice(&1u32.to_le_bytes());
    view.extend_from_slice(&90_000u64.to_le_bytes());
    view.extend_from_slice(&1u32.to_le_bytes());
    view.push(0x51);
    view
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    ensure!(
        fs::metadata(path)?.len() <= MAX_FILE_BYTES,
        "file too large: {}",
        path.display()
    );
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    ensure!(
        bytes.len() as u64 <= MAX_FILE_BYTES,
        "file grew beyond byte limit"
    );
    Ok(bytes)
}

fn cases<'a>(
    initial: [u32; 2],
    parameters: &'a [u8],
    view: &'a [u8],
    witness: &'a [u8],
) -> Result<Vec<Case<'a>>> {
    let make = |name, p, v, w, accept| Case {
        name,
        parameters: p,
        view: v,
        witness: w,
        accept,
    };
    let mut cases = vec![make(
        "valid",
        parameters.into(),
        view.into(),
        witness.into(),
        true,
    )];

    let mut changed = initial;
    changed[0] = (changed[0] + 1) % MODULUS;
    cases.push(make(
        "changed-initial",
        encode_parameters(&Parameters { initial: changed }).into(),
        view.into(),
        witness.into(),
        false,
    ));

    let mut proof =
        decode_witness(witness).map_err(|e| anyhow::anyhow!("decoding fixture: {e:?}"))?;
    let output = proof.output;
    proof.output[0] = (proof.output[0] + 1) % MODULUS;
    cases.push(make(
        "changed-output",
        parameters.into(),
        view.into(),
        encode_witness(&proof).into(),
        false,
    ));
    proof.output = output;
    let config = proof.stark.config;
    proof.stark.0.config.fri_config.n_queries = 0;
    cases.push(make(
        "changed-security-config",
        parameters.into(),
        view.into(),
        encode_witness(&proof).into(),
        false,
    ));
    proof.stark.0.config = config;
    proof.stark.0.commitments[0].0[0] ^= 1;
    cases.push(make(
        "changed-selector-root",
        parameters.into(),
        view.into(),
        encode_witness(&proof).into(),
        false,
    ));
    proof.stark.0.commitments[0].0[0] ^= 1;

    let mut changed_view = view.to_vec();
    changed_view[0] ^= 1; // Still a well-formed view; changes public context.
    cases.push(make(
        "changed-context",
        parameters.into(),
        changed_view.into(),
        witness.into(),
        false,
    ));

    let mut corrupt = witness.to_vec();
    let middle = corrupt.len() / 2;
    corrupt[middle] ^= 1;
    cases.push(make(
        "corrupt-proof",
        parameters.into(),
        view.into(),
        corrupt.into(),
        false,
    ));
    cases.push(make(
        "truncated-proof",
        parameters.into(),
        view.into(),
        (&witness[..witness.len() - 1]).into(),
        false,
    ));
    let mut trailing = witness.to_vec();
    trailing.push(0);
    cases.push(make(
        "trailing-proof-byte",
        parameters.into(),
        view.into(),
        trailing.into(),
        false,
    ));

    cases.push(make(
        "noncanonical-initial",
        encode_parameters(&Parameters {
            initial: [MODULUS, initial[1]],
        })
        .into(),
        view.into(),
        witness.into(),
        false,
    ));
    proof.output[0] = MODULUS;
    cases.push(make(
        "noncanonical-output",
        parameters.into(),
        view.into(),
        encode_witness(&proof).into(),
        false,
    ));
    let mut malformed_view = view.to_vec();
    malformed_view[8..12].copy_from_slice(&1u32.to_le_bytes()); // One input, index one invalid.
    cases.push(make(
        "invalid-selected-input",
        parameters.into(),
        malformed_view.into(),
        witness.into(),
        false,
    ));
    let mut trailing_parameters = parameters.to_vec();
    trailing_parameters.push(0);
    cases.push(make(
        "trailing-parameter-byte",
        trailing_parameters.into(),
        view.into(),
        witness.into(),
        false,
    ));
    cases.push(make(
        "empty-proof",
        parameters.into(),
        view.into(),
        (&[][..]).into(),
        false,
    ));
    Ok(cases)
}

fn check_native(cases: &[Case<'_>], root: [u8; 32]) -> Result<usize> {
    for case in cases {
        let accepted =
            verify_bytes(&case.parameters, &context(&case.view), &case.witness, root).is_ok();
        ensure!(
            accepted == case.accept,
            "native case {}: accepted={accepted}, expected={}",
            case.name,
            case.accept
        );
    }
    let valid = &cases[0];
    let mut wrong_root = root;
    wrong_root[0] ^= 1;
    ensure!(
        verify_bytes(
            &valid.parameters,
            &context(&valid.view),
            &valid.witness,
            wrong_root
        )
        .is_err(),
        "native verifier accepted an unpinned selector root"
    );
    Ok(cases.len() + 1)
}

fn generate(directory: &Path, root_path: &Path) -> Result<()> {
    fs::create_dir_all(directory)?;
    let root = preprocessed_root()?;
    let mut report = Vec::new();
    for (index, (name, initial)) in FIXTURES.into_iter().enumerate() {
        let view = synthetic_view(index as u8 + 7);
        let started = Instant::now();
        let fixture = prove_computation(initial, &context(&view))?;
        let proving_seconds = started.elapsed().as_secs_f64();
        ensure!(
            fixture.preprocessed_root == root,
            "selector root varies with public inputs"
        );
        ensure!(
            fixture.output == check_computation(initial)?,
            "incorrect public recurrence output"
        );
        let checks = check_native(
            &cases(initial, &fixture.parameters, &view, &fixture.witness)?,
            root,
        )?;
        let metadata = Metadata {
            initial,
            output: fixture.output,
            preprocessed_root: root,
            log_size: fixture.log_size,
            witness_bytes: fixture.witness.len(),
            proving_seconds,
        };
        let path = directory.join(name);
        fs::create_dir_all(&path)?;
        fs::write(path.join("parameters.bin"), &fixture.parameters)?;
        fs::write(path.join("witness.bin"), &fixture.witness)?;
        fs::write(path.join("view.bin"), &view)?;
        fs::write(
            path.join("metadata.json"),
            serde_json::to_vec_pretty(&metadata)?,
        )?;
        report.push(json!({"fixture": name, "metadata": metadata, "native_checks_passed": checks}));
    }
    if let Some(parent) = root_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(root_path, root)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "mode": "public-recurrence-non-signing", "steps": 1023,
            "privacy_claim": false, "authorization_claim": false,
            "like_for_like_sha256_comparison": false, "fixtures": report,
        }))?
    );
    Ok(())
}

fn measure(module_path: &Path, directory: &Path, diagnostic: bool) -> Result<()> {
    let bytes = read_bounded(module_path)?;
    let root = preprocessed_root()?;
    let production = MeteredGuest::new(&bytes, INSTANCE_FUEL, Admission::Scored);
    let admission_error = production.as_ref().err().map(|e| format!("{e:#}"));
    let guest = if diagnostic {
        // Waive only module byte admission; retain the real fuel/input limits.
        Some(MeteredGuest::new(
            &bytes,
            INSTANCE_FUEL,
            Admission::LegacyDiagnostic,
        )?)
    } else {
        production.ok()
    };
    let mut passed = admission_error.is_none() && !diagnostic;
    let mut results = Vec::new();
    let mut wasm_cases_exercised = 0usize;
    let mut wasm_cases_failed = 0usize;
    for (name, _) in FIXTURES {
        let path = directory.join(name);
        let metadata: Metadata =
            serde_json::from_slice(&read_bounded(&path.join("metadata.json"))?)?;
        ensure!(
            metadata.preprocessed_root == root,
            "fixture root differs from the fixed circuit"
        );
        let parameters = read_bounded(&path.join("parameters.bin"))?;
        let witness = read_bounded(&path.join("witness.bin"))?;
        let view = read_bounded(&path.join("view.bin"))?;
        let cases = cases(metadata.initial, &parameters, &view, &witness)?;
        let native_checks = check_native(&cases, root)?;
        let input_error = runtime::validate_inputs(&parameters, &view, &witness)
            .err()
            .map(|e| format!("{e:#}"));
        let mut measurements = Vec::new();
        if let Some(guest) = &guest {
            if input_error.is_none() {
                for case in &cases {
                    wasm_cases_exercised += 1;
                    match guest.measure(&case.parameters, &case.view, &case.witness) {
                        Ok(measured) => {
                            let correct = if case.accept {
                                measured.result == 1
                            } else {
                                matches!(measured.result, -1 | 0)
                            };
                            passed &= correct;
                            wasm_cases_failed += usize::from(!correct);
                            measurements.push(json!({
                                "case": case.name, "expected_accept": case.accept, "correct": correct,
                                "return": measured.result, "fuel": measured.fuel,
                                "linear_memory_bytes": measured.memory_bytes,
                                "heap_peak_requested_bytes": measured.heap_peak_requested_bytes,
                                "elapsed_seconds": measured.elapsed.as_secs_f64(),
                            }));
                        }
                        Err(error) => {
                            passed = false;
                            wasm_cases_failed += 1;
                            measurements.push(json!({"case": case.name, "expected_accept": case.accept, "correct": false, "error": format!("{error:#}")}));
                        }
                    }
                }
            }
        }
        if input_error.is_some() {
            passed = false;
        }
        results.push(json!({
            "fixture": name, "metadata": metadata, "parameters_bytes": parameters.len(),
            "witness_bytes": witness.len(), "signed_view_bytes": view.len(),
            "native_checks_passed": native_checks, "input_admission_error": input_error,
            "wasm_cases": measurements,
        }));
    }
    let report = json!({
        "mode": if diagnostic { "diagnostic-only-non-signing" } else { "production-limits-non-signing" },
        "stwo_version": "2.3.0", "trace_rows": 1024, "steps": 1023,
        "privacy_claim": false, "authorization_claim": false,
        "like_for_like_sha256_comparison": false,
        "module_bytes": bytes.len(), "module_sha256": format!("{:x}", Sha256::digest(&bytes)),
        "limits": {"program_bytes": MAX_PROGRAM_BYTES, "parameters_bytes": MAX_PARAMETER_BYTES,
            "witness_bytes": emulator_connect::program::MAX_WITNESS_BYTES, "fuel": INSTANCE_FUEL,
            "heap_backing_bytes": 256 * 1024, "linear_memory_bytes": 64 * 1024 * 1024},
        "measured_fuel_allowance": INSTANCE_FUEL,
        "production_admission_error": admission_error,
        "fits_production_limits_and_passes_cases": passed,
        "compile_seconds": guest.as_ref().map(|g| g.compile_time.as_secs_f64()),
        "wasm_cases_exercised": wasm_cases_exercised,
        "wasm_cases_failed": wasm_cases_failed,
        "fixtures": results,
    });
    fs::write(
        directory.join(if diagnostic {
            "diagnostic.json"
        } else {
            "measurement.json"
        }),
        serde_json::to_vec_pretty(&report)?,
    )?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    // A negative feasibility result is useful output, but never a passing gate.
    if !passed && !diagnostic {
        bail!("candidate did not pass unchanged production limits; see measurement.json");
    }
    if diagnostic {
        ensure!(
            wasm_cases_exercised > 0 && wasm_cases_failed == 0,
            "diagnostic WASM correctness failed or no cases executed; see diagnostic.json"
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.first().and_then(|s| s.to_str()) {
        Some("generate") if args.len() == 3 => generate(Path::new(&args[1]), Path::new(&args[2])),
        Some("measure") if args.len() == 3 => measure(Path::new(&args[1]), Path::new(&args[2]), false),
        Some("measure") if args.len() == 4 && args[3] == "--diagnostic" => measure(Path::new(&args[1]), Path::new(&args[2]), true),
        _ => bail!("usage: checkstwo-probe generate FIXTURE_DIRECTORY ROOT_FILE | measure MODULE FIXTURE_DIRECTORY [--diagnostic]"),
    }
}
