//! Reusable Groth16 proof checking only. No signing, transaction projection, or
//! caller-supplied digest is interpreted as spend authorization.
mod fixtures;
#[path = "../../probe/src/runtime.rs"]
mod runtime;

use anyhow::{bail, ensure, Context, Result};
use checkzkp_generic_guest::MAX_ARGUMENT_BYTES;
use fixtures::{Corpus, Expected, Fixture};
use runtime::{Admission, Measurement, MeteredGuest};
use sapio_base::program::MAX_PROGRAM_BYTES;
use sapio_wasm::host::INSTANCE_FUEL;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

// Harness file bounds only; these do not change the engine's production limits.
const MAX_CORPUS_BYTES: usize = 64 * 1024 * 1024;
const MAX_DIAGNOSTIC_MODULE_BYTES: usize = 4 * 1024 * 1024;
const USAGE: &str = "Usage:
  checkzkp-generic-probe --generate-corpus PATH
  checkzkp-generic-probe --benchmark MODULE CORPUS [--legacy-diagnostic] [--diagnostic-fuel N]
  checkzkp-generic-probe --verify MODULE VK_FILE PROOF_FILE PUBLIC_INPUTS_FILE [--legacy-diagnostic] [--diagnostic-fuel N]

Files for --verify contain raw arkworks 0.5 CanonicalSerialize uncompressed bytes,
not hex. Encodings must exactly match CanonicalSerialize output: sign/infinity
aliases accepted by Deserialize alone are rejected; canonical identity is valid.
Corpus format_version=1 uses hex strings and strict fields. Default fuel is
100000000 and module cap is 65536 bytes. --legacy-diagnostic waives only the
module byte cap (4 MiB harness maximum). --diagnostic-fuel N requires that flag
and a positive finite integer. Diagnostic results do not establish deployability.
This primitive checks proof validity only; it does not authorize spending.";

#[derive(Clone, Copy)]
struct Allowance {
    legacy_diagnostic: bool,
    fuel: u64,
}

impl Allowance {
    fn parse(arguments: &[OsString]) -> Result<Self> {
        let mut legacy_diagnostic = false;
        let mut diagnostic_fuel = None;
        let mut arguments = arguments.iter();
        while let Some(argument) = arguments.next() {
            match argument.to_str() {
                Some("--legacy-diagnostic") => {
                    ensure!(!legacy_diagnostic, "duplicate --legacy-diagnostic");
                    legacy_diagnostic = true;
                }
                Some("--diagnostic-fuel") => {
                    ensure!(diagnostic_fuel.is_none(), "duplicate --diagnostic-fuel");
                    let value = arguments.next().context("--diagnostic-fuel requires N")?;
                    let fuel: u64 = value
                        .to_str()
                        .context("fuel must be a finite positive integer")?
                        .parse()
                        .context("fuel must be a finite positive integer")?;
                    ensure!(fuel > 0, "fuel must be positive");
                    diagnostic_fuel = Some(fuel);
                }
                _ => bail!("unknown option {argument:?}\n{USAGE}"),
            }
        }
        ensure!(
            legacy_diagnostic || diagnostic_fuel.is_none(),
            "--diagnostic-fuel requires explicit --legacy-diagnostic"
        );
        Ok(Self {
            legacy_diagnostic,
            fuel: diagnostic_fuel.unwrap_or(INSTANCE_FUEL),
        })
    }

    fn module_bound(self) -> usize {
        if self.legacy_diagnostic {
            MAX_DIAGNOSTIC_MODULE_BYTES
        } else {
            MAX_PROGRAM_BYTES
        }
    }

    fn admission(self) -> Admission {
        if self.legacy_diagnostic {
            Admission::LegacyDiagnostic
        } else {
            Admission::Scored
        }
    }

    fn describe(self) {
        let admission = if self.legacy_diagnostic {
            "legacy-diagnostic"
        } else {
            "scored"
        };
        println!("GROTH16 admission={admission} allowance={} module_byte_cap={} production_allowance={INSTANCE_FUEL} production_module_byte_cap={MAX_PROGRAM_BYTES}", self.fuel, self.module_bound());
        println!("Proof-checking primitive only: no signing and no transaction authorization policy. All VK validation, key preparation, and official proof verification execute inside each fresh WASM instance.");
        if self.legacy_diagnostic {
            println!("EXPLICIT LEGACY DIAGNOSTIC: code-size waiver only; harness maximum={MAX_DIAGNOSTIC_MODULE_BYTES} bytes; other engine/input bounds unchanged. Not evidence of production deployability.");
        }
        if self.fuel != INSTANCE_FUEL {
            println!("EXPLICIT DIAGNOSTIC FUEL: allowance={} replaces production allowance={INSTANCE_FUEL}; finite per-instance meter, no refunds or unmetered guest calls.", self.fuel);
        }
    }
}

enum Command {
    Generate(PathBuf),
    Benchmark {
        module: PathBuf,
        corpus: PathBuf,
        allowance: Allowance,
    },
    Verify {
        module: PathBuf,
        key: PathBuf,
        proof: PathBuf,
        inputs: PathBuf,
        allowance: Allowance,
    },
    Help,
}

fn options() -> Result<Command> {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    match arguments.first().and_then(|argument| argument.to_str()) {
        Some("--generate-corpus") => {
            ensure!(arguments.len() == 2, "{USAGE}");
            Ok(Command::Generate(PathBuf::from(&arguments[1])))
        }
        Some("--benchmark") => {
            ensure!(arguments.len() >= 3, "{USAGE}");
            Ok(Command::Benchmark {
                module: PathBuf::from(&arguments[1]),
                corpus: PathBuf::from(&arguments[2]),
                allowance: Allowance::parse(&arguments[3..])?,
            })
        }
        Some("--verify") => {
            ensure!(arguments.len() >= 5, "{USAGE}");
            Ok(Command::Verify {
                module: PathBuf::from(&arguments[1]),
                key: PathBuf::from(&arguments[2]),
                proof: PathBuf::from(&arguments[3]),
                inputs: PathBuf::from(&arguments[4]),
                allowance: Allowance::parse(&arguments[5..])?,
            })
        }
        Some("--help") if arguments.len() == 1 => Ok(Command::Help),
        _ => bail!("{USAGE}"),
    }
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "{} is not a regular file",
        path.display()
    );
    ensure!(
        metadata.len() <= maximum as u64,
        "{} exceeds {maximum} bytes",
        path.display()
    );
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= maximum,
        "{} grew beyond {maximum} bytes",
        path.display()
    );
    Ok(bytes)
}

fn print_hash(name: &str, bytes: &[u8]) {
    println!(
        "GROTH16 {name}_sha256={}",
        hex::encode(Sha256::digest(bytes))
    );
}

fn generate(path: &Path) -> Result<()> {
    // Check cheaply before setup, then enforce no-overwrite atomically at write.
    ensure!(
        !path.try_exists()?,
        "refusing to overwrite {}",
        path.display()
    );
    println!("Reference: {}", fixtures::REFERENCE_DESCRIPTION);
    let corpus = fixtures::generate()?;
    let mut bytes = serde_json::to_vec_pretty(&corpus)?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() <= MAX_CORPUS_BYTES,
        "generated corpus exceeds harness file bound"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating {} without overwrite", path.display()))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    print_hash("corpus", &bytes);
    for case in &corpus.cases {
        println!("FIXTURE name={:?} expected={} verifying_key_bytes={} proof_bytes={} public_inputs_bytes={}", case.name, case.expected.name(), case.verifying_key.len(), case.proof.len(), case.public_inputs.len());
    }
    println!("Generated {} public cases at {}; fresh OS-random local experimental setups/proofs, no secrets or proving keys written. Algebraically constructed identity-IC cases are separately named and are not production setup claims.", corpus.cases.len(), path.display());
    println!("Unused R1CS inputs use the unchanged official reduction and fresh proofs for changed values. The separately constructed identity-IC pair reuses one proof across two scalar values. Neither workload defines application authorization.");
    Ok(())
}

#[derive(Default)]
struct Totals {
    completed: usize,
    full_completed: usize,
    replays: usize,
    failures: usize,
    maximum_full_fuel: u64,
    maximum_memory_bytes: u64,
}

impl Totals {
    fn observe(&mut self, full: bool, measurement: &Measurement) {
        self.completed += 1;
        self.maximum_memory_bytes = self.maximum_memory_bytes.max(measurement.memory_bytes);
        if full {
            self.full_completed += 1;
            self.maximum_full_fuel = self.maximum_full_fuel.max(measurement.fuel);
        }
    }
}

fn run_case(
    guest: &MeteredGuest,
    fixture: &Fixture,
    replay_after: Option<&str>,
    totals: &mut Totals,
) -> bool {
    if replay_after.is_some() {
        totals.replays += 1;
    }
    match guest.measure(
        &fixture.verifying_key,
        &fixture.public_inputs,
        &fixture.proof,
    ) {
        Ok(measured) => {
            totals.observe(fixture.expected != Expected::Malformed, &measured);
            let verdict = Expected::from_result(measured.result);
            let correct = verdict
                .as_ref()
                .is_ok_and(|verdict| *verdict == fixture.expected);
            let verdict = verdict
                .map(|value| value.name())
                .unwrap_or("invalid_return_code");
            println!("CASE name={:?} replay_after={replay_after:?} expected={} verdict={verdict} result={} fuel={} linear_memory_bytes={} elapsed_ms={:.3} match={correct}", fixture.name, fixture.expected.name(), measured.result, measured.fuel, measured.memory_bytes, measured.elapsed.as_secs_f64() * 1000.0);
            if !correct {
                totals.failures += 1;
            }
            correct
        }
        Err(error) => {
            // A trap, exhausted meter, host error, or allocation error is NEVER
            // accepted as a rejection or hidden from full-case accounting.
            totals.failures += 1;
            println!("CASE name={:?} replay_after={replay_after:?} expected={} verdict=execution_error fuel=unavailable linear_memory_bytes=unavailable error={error:#}", fixture.name, fixture.expected.name());
            false
        }
    }
}

fn benchmark(module_path: &Path, corpus_path: &Path, allowance: Allowance) -> Result<()> {
    allowance.describe();
    println!("Reference: {}", fixtures::REFERENCE_DESCRIPTION);
    let module = read_bounded(module_path, allowance.module_bound())?;
    let corpus_bytes = read_bounded(corpus_path, MAX_CORPUS_BYTES)?;
    print_hash("module", &module);
    print_hash("corpus", &corpus_bytes);
    let corpus: Corpus =
        serde_json::from_slice(&corpus_bytes).context("decoding strict public corpus")?;
    let valid = fixtures::validate(&corpus)?;
    let guest = MeteredGuest::for_groth16(&module, allowance.fuel, allowance.admission())?;
    let mut totals = Totals::default();
    let full_cases = corpus
        .cases
        .iter()
        .filter(|case| case.expected != Expected::Malformed)
        .count();
    for fixture in &corpus.cases {
        let correct = run_case(&guest, fixture, None, &mut totals);
        if fixture.expected != Expected::Accept || !correct {
            // measure() always creates a new Store/Instance. Replay even after
            // a trap or out-of-fuel result, but never erase the original failure.
            run_case(&guest, valid, Some(&fixture.name), &mut totals);
        }
    }
    if totals.failures != 0 {
        println!("INCOMPLETE failures={} attempted_cases={} replay_attempts={} completed_calls={} completed_full_calls={} maximum_COMPLETED_full_verification_fuel={} (NOT a complete worst-case result)", totals.failures, corpus.cases.len(), totals.replays, totals.completed, totals.full_completed, totals.maximum_full_fuel);
        bail!("{} WASM case/replay failures; no successful benchmark metric emitted; traps and exhausted fuel are not rejections", totals.failures);
    }
    ensure!(
        totals.completed == corpus.cases.len() + totals.replays,
        "not every case and replay completed"
    );
    ensure!(
        totals.full_completed == full_cases + totals.replays,
        "not every full case and valid replay was included"
    );
    println!("PASS all native labels, all fresh-instance WASM cases, and valid replays after failures. Full verification includes input allocation, canonical decoding, VK validation, key preparation, MSM, and official pairing verification; no native preparation or excluded full cases.");
    println!("METRIC module_bytes={}", module.len());
    println!("METRIC allowance={}", allowance.fuel);
    println!("METRIC guest_cases={}", corpus.cases.len());
    println!("METRIC full_cases={full_cases}");
    println!("METRIC valid_replays={}", totals.replays);
    println!("METRIC linear_memory_bytes={}", totals.maximum_memory_bytes);
    println!(
        "METRIC compile_ms={:.3}",
        guest.compile_time.as_secs_f64() * 1000.0
    );
    println!(
        "METRIC maximum_full_verification_fuel={}",
        totals.maximum_full_fuel
    );
    Ok(())
}

fn verify(
    module_path: &Path,
    key_path: &Path,
    proof_path: &Path,
    inputs_path: &Path,
    allowance: Allowance,
) -> Result<()> {
    allowance.describe();
    let module = read_bounded(module_path, allowance.module_bound())?;
    let key = read_bounded(key_path, MAX_ARGUMENT_BYTES)?;
    let proof = read_bounded(proof_path, MAX_ARGUMENT_BYTES)?;
    let inputs = read_bounded(inputs_path, MAX_ARGUMENT_BYTES)?;
    print_hash("module", &module);
    print_hash("verifying_key", &key);
    print_hash("proof", &proof);
    print_hash("public_inputs", &inputs);
    let guest = MeteredGuest::for_groth16(&module, allowance.fuel, allowance.admission())?;
    // Do not replace the requested WASM verification with a native precheck.
    let measured = guest.measure(&key, &inputs, &proof).context(
        "actual WASM verification failed; traps/fuel exhaustion are not false equations",
    )?;
    let verdict = Expected::from_result(measured.result)?;
    println!(
        "VERIFY verdict={} result={} fuel={} linear_memory_bytes={} elapsed_ms={:.3}",
        verdict.name(),
        measured.result,
        measured.fuel,
        measured.memory_bytes,
        measured.elapsed.as_secs_f64() * 1000.0
    );
    ensure!(
        verdict == Expected::Accept,
        "proof is {}; not successful verification",
        verdict.name()
    );
    println!(
        "Valid Groth16 proof for the supplied VK/public inputs; NOT a spending authorization."
    );
    Ok(())
}

fn main() -> Result<()> {
    match options()? {
        Command::Generate(path) => generate(&path),
        Command::Benchmark {
            module,
            corpus,
            allowance,
        } => benchmark(&module, &corpus, allowance),
        Command::Verify {
            module,
            key,
            proof,
            inputs,
            allowance,
        } => verify(&module, &key, &proof, &inputs, allowance),
        Command::Help => {
            println!("{USAGE}");
            Ok(())
        }
    }
}
