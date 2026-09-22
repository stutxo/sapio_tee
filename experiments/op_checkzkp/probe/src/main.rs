//! Local-only Groth16 feasibility experiment. Synthetic funding, no network.
//! Diagnostic mode may bypass module admission and increase fuel; it never signs.
use anyhow::{bail, ensure, Context, Result};
use bitcoin::bip32::Xpriv;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{rand::RngCore, Secp256k1, XOnlyPublicKey};
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};
use checkzkp_prover::DemoProver;
use emulator_connect::program::{
    validate_program_response, ProgramError, ProgramOracle, ProgramSigningRequest,
    ProgramSpendPath, WasmEvaluator, PSBT,
};
use sapio_base::program::{ProgramInstance, MAX_PROGRAM_BYTES};
use sapio_wasm::host::{add_crypto_imports, bind_crypto, new_evaluator_store, INSTANCE_FUEL};
use std::path::PathBuf;
use std::time::Instant;
use wasmer::{Imports, Instance, Module, Store, TypedFunction};
use wasmer_middlewares::metering::{get_remaining_points, set_remaining_points, MeteringPoints};

type Arguments = (i32, i32, i32, i32, i32, i32, i32, i32);

fn options() -> Result<(PathBuf, Option<u64>)> {
    let mut args = std::env::args_os().skip(1);
    let path = args
        .next()
        .context("usage: checkzkp-probe MODULE.wasm [--diagnostic-fuel UNITS]")?;
    let fuel = match args.next() {
        None => None,
        Some(flag) if flag == "--diagnostic-fuel" => {
            let value = args.next().context("missing diagnostic fuel")?;
            let fuel = value.to_str().context("invalid fuel encoding")?.parse()?;
            ensure!(fuel > 0, "fuel must be positive");
            Some(fuel)
        }
        Some(_) => bail!("unknown argument"),
    };
    ensure!(args.next().is_none(), "unexpected trailing arguments");
    Ok((path.into(), fuel))
}

fn transaction(key: XOnlyPublicKey) -> Result<Psbt> {
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::from_consensus(800_000),
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([7; 32]), 0),
            sequence: bitcoin::Sequence(0xffff_fffd),
            ..TxIn::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(99_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([42; 20])),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx)?;
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: ScriptBuf::new_p2tr(&Secp256k1::verification_only(), key, None),
    });
    psbt.inputs[0].tap_internal_key = Some(key);
    Ok(psbt)
}

/// Pinned Sapio v1 encoding (ctv_emulators/src/program/wasm.rs::encode_view).
/// The upstream encoder is private; successful oracle signing cross-checks this
/// client encoding against the actual host projection. Selected input is zero.
fn view(psbt: &Psbt) -> Result<Vec<u8>> {
    let tx = &psbt.unsigned_tx;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&tx.version.0.to_le_bytes());
    bytes.extend_from_slice(&tx.lock_time.to_consensus_u32().to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&(tx.input.len() as u32).to_le_bytes());
    for (input, metadata) in tx.input.iter().zip(&psbt.inputs) {
        let prevout = metadata
            .witness_utxo
            .as_ref()
            .context("missing previous output")?;
        input.previous_output.consensus_encode(&mut bytes)?;
        bytes.extend_from_slice(&input.sequence.0.to_le_bytes());
        bytes.extend_from_slice(&prevout.value.to_sat().to_le_bytes());
        bytes.extend_from_slice(&(prevout.script_pubkey.len() as u32).to_le_bytes());
        bytes.extend_from_slice(prevout.script_pubkey.as_bytes());
    }
    bytes.extend_from_slice(&(tx.output.len() as u32).to_le_bytes());
    for output in &tx.output {
        bytes.extend_from_slice(&output.value.to_sat().to_le_bytes());
        bytes.extend_from_slice(&(output.script_pubkey.len() as u32).to_le_bytes());
        bytes.extend_from_slice(output.script_pubkey.as_bytes());
    }
    Ok(bytes)
}

struct MeteredGuest {
    store: Store,
    module: Module,
    fuel: u64,
}

impl MeteredGuest {
    fn new(bytes: &[u8], fuel: u64) -> Result<Self> {
        let store = new_evaluator_store();
        let start = Instant::now();
        let module = Module::new(&store, bytes)?;
        for import in module.imports() {
            ensure!(
                import.module() == "sapio_crypto_v1" && import.name() == "sha256",
                "unexpected guest import {}::{}",
                import.module(),
                import.name()
            );
        }
        println!(
            "WASM compilation: {:.3}s; ZKP arithmetic has no native imports",
            start.elapsed().as_secs_f64()
        );
        Ok(Self {
            store,
            module,
            fuel,
        })
    }

    fn evaluate(
        &mut self,
        parameters: &[u8],
        view: &[u8],
        witness: &[u8],
        label: &str,
    ) -> Result<i32> {
        let mut imports = Imports::new();
        let crypto = add_crypto_imports(&mut self.store, &mut imports);
        let instance = Instance::new(&mut self.store, &self.module, &imports)?;
        bind_crypto(&crypto, &mut self.store, &instance)?;
        if self.fuel != INSTANCE_FUEL {
            set_remaining_points(&mut self.store, &instance, self.fuel);
        }
        let memory = instance.exports.get_memory("memory")?;
        let alloc: TypedFunction<i32, i32> = instance
            .exports
            .get_typed_function(&self.store, "sapio_alloc_v1")?;
        let evaluate: TypedFunction<Arguments, i32> = instance
            .exports
            .get_typed_function(&self.store, "sapio_evaluate_v1")?;
        let started = Instant::now();
        let mut pointers = [0i32; 3];
        for (slot, bytes) in pointers.iter_mut().zip([parameters, view, witness]) {
            *slot = alloc.call(&mut self.store, bytes.len() as i32)?;
        }
        for (pointer, bytes) in pointers.iter().zip([parameters, view, witness]) {
            memory
                .view(&self.store)
                .write(u64::from(*pointer as u32), bytes)?;
        }
        let result = evaluate.call(
            &mut self.store,
            0,
            0,
            pointers[0],
            parameters.len() as i32,
            pointers[1],
            view.len() as i32,
            pointers[2],
            witness.len() as i32,
        );
        let fuel = match get_remaining_points(&mut self.store, &instance) {
            MeteringPoints::Remaining(left) => format!("{}", self.fuel - left),
            MeteringPoints::Exhausted => format!(">={} (exhausted)", self.fuel),
        };
        let outcome = match &result {
            Ok(value) => format!("return {value}"),
            Err(error) => format!("trap: {error}"),
        };
        println!(
            "{label}: {outcome}; fuel={fuel}; memory={} bytes; elapsed={:.3}s",
            memory.view(&self.store).data_size(),
            started.elapsed().as_secs_f64()
        );
        result.with_context(|| format!("{label} failed to complete"))
    }
}

fn invalid_proof(witness: &[u8]) -> Vec<u8> {
    // Valid prime-order G1 point, wrong Groth16 A: exercises the pairing equation,
    // not just malformed-point decoding. BN254 G1 generator is (1, 2).
    let mut invalid = witness.to_vec();
    invalid[..64].fill(0);
    invalid[31] = 1;
    invalid[63] = 2;
    invalid
}

fn changed_transaction(psbt: &Psbt) -> Psbt {
    let mut changed = psbt.clone();
    changed.unsigned_tx.output[0].value = Amount::from_sat(98_999);
    changed
}

fn prove(prover: &DemoProver, psbt: &Psbt) -> Result<Vec<u8>> {
    let view = view(psbt)?;
    let started = Instant::now();
    let witness = prover.prove(&view)?;
    println!(
        "Proof generation: {:.3}s; witness={} bytes; view={} bytes",
        started.elapsed().as_secs_f64(),
        witness.len(),
        view.len()
    );
    Ok(witness)
}

fn exercise(
    prover: &DemoProver,
    module: &[u8],
    parameters: &[u8],
    psbt: &Psbt,
    witness: &[u8],
    fuel: u64,
) -> Result<()> {
    let view = view(psbt)?;
    ensure!(
        prover.verify(&view, witness)?,
        "native verifier rejected valid proof"
    );
    let invalid = invalid_proof(witness);
    ensure!(
        !prover.verify(&view, &invalid)?,
        "native verifier accepted invalid proof"
    );
    let changed = self::view(&changed_transaction(psbt))?;
    ensure!(
        !prover.verify(&changed, witness)?,
        "native verifier accepted changed transaction"
    );
    println!("PASS independent arkworks reference: valid / invalid / changed transaction");

    let mut guest = MeteredGuest::new(module, fuel)?;
    ensure!(
        guest.evaluate(parameters, &view, witness, "valid proof")? == 1,
        "valid proof rejected"
    );
    ensure!(
        guest.evaluate(parameters, &view, &invalid, "invalid on-curve proof")? == 0,
        "invalid proof accepted"
    );
    ensure!(
        guest.evaluate(parameters, &changed, witness, "changed transaction")? == 0,
        "proof replay accepted"
    );
    ensure!(
        guest.evaluate(
            parameters,
            &view,
            witness.get(..287).context("short fixture")?,
            "truncated witness"
        )? != 1,
        "truncated witness accepted"
    );
    let mut trailing = witness.to_vec();
    trailing.push(0);
    ensure!(
        guest.evaluate(parameters, &view, &trailing, "trailing witness byte")? != 1,
        "trailing data accepted"
    );
    let mut malformed = witness.to_vec();
    malformed[..32].fill(0xff);
    ensure!(
        guest.evaluate(parameters, &view, &malformed, "noncanonical coordinate")? != 1,
        "noncanonical point accepted"
    );
    malformed[..64].fill(0);
    ensure!(
        guest.evaluate(parameters, &view, &malformed, "infinity encoding")? != 1,
        "infinity accepted"
    );
    // Every case gets a fresh instance, as it does in ProgramOracle.
    ensure!(
        guest.evaluate(parameters, &view, witness, "valid proof after rejections")? == 1,
        "rejections affected fresh instance"
    );
    Ok(())
}

fn main() -> Result<()> {
    let (path, diagnostic_fuel) = options()?;
    let module = std::fs::read(path)?;
    println!(
        "Module: {} bytes; production limit: {MAX_PROGRAM_BYTES}; production fuel: {INSTANCE_FUEL}",
        module.len()
    );
    if diagnostic_fuel.is_none() && module.len() > MAX_PROGRAM_BYTES {
        // Obtain the actual pinned runtime's error, not an inferred rejection.
        WasmEvaluator::new(module).context("production module admission")?;
        bail!("runtime unexpectedly admitted an oversized module");
    }
    if let Some(fuel) = diagnostic_fuel {
        println!("DIAGNOSTIC ONLY: module admission bypassed, fuel={fuel}; no signing; not evidence of deployability");
    }
    let mut seed = [0u8; 32];
    bitcoin::secp256k1::rand::thread_rng().fill_bytes(&mut seed);
    let root = Xpriv::new_master(Network::Regtest, &seed)?;
    let oracle = ProgramOracle::new(root, vec![])?;
    let started = Instant::now();
    let prover = DemoProver::new()?;
    println!(
        "Fresh experimental trusted setup: {:.3}s; secrets remain in this process",
        started.elapsed().as_secs_f64()
    );
    let parameters = prover.parameters();
    if let Some(fuel) = diagnostic_fuel {
        let psbt = transaction(oracle.public_root().public_key.x_only_public_key().0)?;
        let witness = prove(&prover, &psbt)?;
        println!("Parameters: {} bytes", parameters.len());
        exercise(&prover, &module, &parameters, &psbt, &witness, fuel)?;
        println!("PASS diagnostic WASM verification only; no oracle signature requested");
        return Ok(());
    }
    let instance = ProgramInstance::wasm(module, parameters)?;
    let psbt = transaction(instance.derive_public_key(&oracle.public_root())?)?;
    let witness = prove(&prover, &psbt)?;
    let request = ProgramSigningRequest {
        instance,
        input_index: 0,
        witness,
        path: ProgramSpendPath::KeyPath,
        psbt: PSBT(psbt),
    };
    let signing = oracle.sign(request.clone());
    match &signing {
        Ok(_) => println!("Actual ProgramOracle: signed"),
        Err(error) => println!("Actual ProgramOracle: {error}"),
    }
    println!("Parameters: {} bytes", request.instance.parameters().len());
    exercise(
        &prover,
        request.instance.program(),
        request.instance.parameters(),
        &request.psbt.0,
        &request.witness,
        INSTANCE_FUEL,
    )?;
    let signed = signing.context("valid proof oracle signing")?;
    validate_program_response(&request, &signed, &oracle.public_root())?;
    println!("PASS actual ProgramOracle signing and signature validation");
    let mut invalid = request.clone();
    invalid.witness = invalid_proof(&invalid.witness);
    ensure!(
        matches!(oracle.sign(invalid), Err(ProgramError::Rejected)),
        "invalid proof must be rejected by predicate, not merely trap"
    );
    let mut changed = request;
    changed.psbt.0 = changed_transaction(&changed.psbt.0);
    ensure!(
        matches!(oracle.sign(changed), Err(ProgramError::Rejected)),
        "changed transaction must be rejected by predicate"
    );
    println!("PASS actual ProgramOracle rejects invalid proof and changed transaction");
    println!("PASS pure-WASM Groth16 under unchanged production limits; synthetic funding only");
    Ok(())
}
