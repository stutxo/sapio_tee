use crate::prepared::{prepare_parameters, PREPARED_PARAMETERS_BYTES};
use crate::runtime::{
    validate_inputs, Admission, Measurement, MeteredGuest, DIAGNOSTIC_FUEL, PHASE_NAMES,
};
use anyhow::{ensure, Context, Result};
use checkzkp_prover::fixtures::{self, Corpus, Expected, Fixture, Kind};
use sapio_base::program::MAX_PROGRAM_BYTES;
use sapio_wasm::host::INSTANCE_FUEL;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

// Harness input-file bounds, not changes to any production resource limit.
const MAX_CORPUS_BYTES: usize = 64 * 1024 * 1024;
const MAX_PROFILE_BYTES: usize = 4 * 1024 * 1024;

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    ensure!(
        file.metadata()?.len() <= maximum as u64,
        "{} exceeds {maximum} bytes",
        path.display()
    );
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= maximum,
        "{} exceeds {maximum} bytes",
        path.display()
    );
    Ok(bytes)
}

fn validate_corpus(corpus: &Corpus) -> Result<&Fixture> {
    ensure!(
        corpus.format_version == 1,
        "unsupported corpus format version {}",
        corpus.format_version
    );
    let mut names = HashSet::new();
    let mut valid = None;
    let mut rejects = 0usize;
    let mut malformed = 0usize;
    for fixture in &corpus.cases {
        ensure!(!fixture.name.is_empty(), "empty fixture name");
        ensure!(
            names.insert(fixture.name.as_str()),
            "duplicate fixture name {:?}",
            fixture.name
        );
        validate_inputs(&fixture.parameters, &fixture.view, &fixture.witness)
            .with_context(|| format!("input bounds for {:?}", fixture.name))?;
        match (&fixture.kind, &fixture.expected) {
            (Kind::Full, Expected::Accept) => {
                valid.get_or_insert(fixture);
            }
            (Kind::Full, Expected::Reject) => rejects += 1,
            (Kind::Malformed, Expected::Malformed) => malformed += 1,
            _ => anyhow::bail!("inconsistent fixture classification for {:?}", fixture.name),
        }
    }
    ensure!(rejects > 0, "corpus has no full-path rejection");
    ensure!(malformed > 0, "corpus has no malformed input");
    let valid = valid.context("corpus has no accepted fixture")?;
    // Parsing and pairing here are independent arkworks code, not the guest's
    // substrate-bn implementation. Labels alone never establish correctness.
    for fixture in &corpus.cases {
        fixtures::verify_fixture(fixture)
            .with_context(|| format!("independent reference disagreed for {:?}", fixture.name))?;
    }
    Ok(valid)
}

fn check_result(fixture: &Fixture, measured: &Measurement) -> Result<()> {
    let matches = match fixture.expected {
        Expected::Accept => measured.result == 1,
        Expected::Reject => measured.result == 0,
        Expected::Malformed => measured.result == 0 || measured.result == -1,
    };
    ensure!(
        matches,
        "guest disagreed for {:?}: returned {}",
        fixture.name,
        measured.result
    );
    Ok(())
}

pub fn generate(path: &Path) -> Result<()> {
    // Check before expensive setup and still use create_new at the actual write
    // boundary, so an intervening file or symlink cannot be overwritten.
    ensure!(
        !path.try_exists()?,
        "refusing to overwrite {}",
        path.display()
    );
    let corpus = fixtures::generate()?;
    validate_corpus(&corpus)?;
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
        .with_context(|| {
            format!(
                "creating public corpus {} without overwrite",
                path.display()
            )
        })?;
    // Corpus's only payload fields are public parameters, views, and witnesses.
    // Neither the prover, secret, proving key, nor setup state is serialized.
    file.write_all(&bytes)?;
    file.sync_all()?;
    println!(
        "Generated {} public fixtures at {}; one-time OS-random setup; no secrets written",
        corpus.cases.len(),
        path.display()
    );
    println!("ASI corpus_sha256={}", hex::encode(Sha256::digest(&bytes)));
    Ok(())
}

pub fn run(module_path: &Path, corpus_path: &Path, profile_path: Option<&Path>) -> Result<()> {
    let module = read_bounded(module_path, MAX_PROGRAM_BYTES)?;
    let corpus_bytes = read_bounded(corpus_path, MAX_CORPUS_BYTES)?;
    let corpus: Corpus =
        serde_json::from_slice(&corpus_bytes).context("decoding strict public corpus")?;
    let valid = validate_corpus(&corpus)?;
    println!("ASI module_sha256={}", hex::encode(Sha256::digest(&module)));
    println!(
        "ASI corpus_sha256={}",
        hex::encode(Sha256::digest(&corpus_bytes))
    );
    println!("DIAGNOSTIC BENCHMARK ONLY: allowance={DIAGNOSTIC_FUEL}; production fuel={INSTANCE_FUEL}; no signing; no deployability claim");
    let guest = MeteredGuest::new(&module, DIAGNOSTIC_FUEL, Admission::Scored)?;
    let mut verification_fuel = 0u64;
    let mut linear_memory_bytes = 0u64;
    let mut verification_time = Duration::ZERO;
    let mut preparation_time = Duration::ZERO;
    let mut preparation_rejections = 0usize;
    let mut guest_cases = 0usize;
    let mut full_cases = 0usize;
    let mut valid_parameters = None;
    for fixture in &corpus.cases {
        // The unchanged raw corpus has already passed the independent arkworks
        // reference. Preparation is deterministic, fixed-key-only work outside
        // guest metering; the guest still meters all prepared-byte decoding.
        let started = Instant::now();
        let prepared = prepare_parameters(&fixture.parameters);
        preparation_time += started.elapsed();
        let parameters = match prepared {
            Ok(parameters) => parameters,
            Err(error) => {
                ensure!(
                    fixture.kind == Kind::Malformed && fixture.expected == Expected::Malformed,
                    "fixed-key preparation failed for full case {:?}: {error:#}",
                    fixture.name
                );
                preparation_rejections += 1;
                println!(
                    "CASE stage=preparation name={:?} result=malformed error={error:#}",
                    fixture.name
                );
                continue;
            }
        };
        validate_inputs(&parameters, &fixture.view, &fixture.witness)
            .with_context(|| format!("prepared input bounds for {:?}", fixture.name))?;
        let measured = guest
            .measure(&parameters, &fixture.view, &fixture.witness)
            .with_context(|| format!("evaluating {:?}", fixture.name))?;
        check_result(fixture, &measured)?;
        guest_cases += 1;
        linear_memory_bytes = linear_memory_bytes.max(measured.memory_bytes);
        if matches!(fixture.kind, Kind::Full) {
            full_cases += 1;
            // Includes every valid, invalid-equation, and transaction-mutated
            // full-path case; never reward a shortcut through malformed input.
            verification_fuel = verification_fuel.max(measured.fuel);
            verification_time = verification_time.max(measured.elapsed);
        }
        println!(
            "CASE stage=guest name={:?} result={} fuel={} linear_memory_bytes={}",
            fixture.name, measured.result, measured.fuel, measured.memory_bytes
        );
        if valid_parameters.is_none() && fixture.expected == Expected::Accept {
            valid_parameters = Some(parameters);
        }
    }
    ensure!(
        full_cases
            == corpus
                .cases
                .iter()
                .filter(|case| case.kind == Kind::Full)
                .count(),
        "not every full-path case reached the guest"
    );
    ensure!(
        guest_cases + preparation_rejections == corpus.cases.len(),
        "corpus case accounting mismatch"
    );
    let valid_parameters = valid_parameters.context("first accepted fixture was not evaluated")?;
    // Use another fresh instance, not a retained post-rejection store.
    fixtures::verify_fixture(valid).context("independent reference replay")?;
    let replay = guest
        .measure(&valid_parameters, &valid.view, &valid.witness)
        .context("valid fixture replay after rejected fixtures")?;
    check_result(valid, &replay)?;
    verification_fuel = verification_fuel.max(replay.fuel);
    verification_time = verification_time.max(replay.elapsed);
    linear_memory_bytes = linear_memory_bytes.max(replay.memory_bytes);

    let profile = if let Some(path) = profile_path {
        let bytes = read_bounded(path, MAX_PROFILE_BYTES)?;
        println!(
            "ASI profile_module_sha256={}",
            hex::encode(Sha256::digest(&bytes))
        );
        let diagnostic = MeteredGuest::new(&bytes, DIAGNOSTIC_FUEL, Admission::Profile)?;
        let measured = diagnostic
            .measure(&valid_parameters, &valid.view, &valid.witness)
            .context("profiling first valid fixture")?;
        check_result(valid, &measured)?;
        let phases = measured
            .phases
            .context("profile did not return phase accounting")?;
        let total = phases
            .iter()
            .try_fold(0u64, |sum, value| sum.checked_add(*value))
            .context("profile phase total overflow")?;
        ensure!(
            total == measured.fuel,
            "profile phases do not sum to measured diagnostic fuel"
        );
        Some((phases, measured.fuel, measured.marker_calls))
    } else {
        None
    };

    // No METRIC line is emitted until every reference, preparation, guest,
    // replay, and optional profile check has succeeded. Never instrument the
    // scored artifact or exclude a full case from its worst-case fuel.
    println!("PASS offline native/WASM corpus and valid replay; timings are secondary; verification_ms is max full-case allocation+verification time; preparation_ms is total raw-key validation+preparation time for all corpus cases, outside guest metering");
    if let Some((phases, total, calls)) = profile {
        println!("PROFILE diagnostic only; fixture={:?}; marker calls={calls}; hook instruction overhead included; phases never substitute for the scored total", valid.name);
        for (index, (name, fuel)) in PHASE_NAMES.iter().zip(phases).enumerate() {
            println!("METRIC profile_phase_{index}_{name}_fuel={fuel}");
        }
        println!("METRIC profile_total_fuel={total}");
        println!("METRIC profile_marker_calls={calls}");
    }
    println!("METRIC module_bytes={}", module.len());
    println!("METRIC linear_memory_bytes={linear_memory_bytes}");
    println!("METRIC prepared_parameters_bytes={PREPARED_PARAMETERS_BYTES}");
    println!("METRIC preparation_rejections={preparation_rejections}");
    println!("METRIC guest_cases={guest_cases}");
    println!("METRIC full_cases={full_cases}");
    println!(
        "METRIC preparation_ms={:.3}",
        preparation_time.as_secs_f64() * 1000.0
    );
    println!(
        "METRIC compile_ms={:.3}",
        guest.compile_time.as_secs_f64() * 1000.0
    );
    println!(
        "METRIC verification_ms={:.3}",
        verification_time.as_secs_f64() * 1000.0
    );
    println!("METRIC verification_fuel={verification_fuel}");
    Ok(())
}
