// Copyright Judica, Inc 2026
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Private Ark adapter for the upstream Sapio evaluator ABI.
//!
//! Execution and encoding are derived from sapio-lang/sapio
//! c8f4e63123e724dc1144075af8ac0dbd3cf4e0b1, ctv_emulators/src/program/wasm.rs.
//! Upstream keeps execution and SignedTransactionView construction private. Only
//! this boundary is adapted: Ark authenticates the aggregate/native spending
//! policy and DEFAULT hash; the upstream host supplies bounded memory, fuel and
//! crypto. No single-key oracle, transaction rewrite or approval token is used.

use anyhow::{ensure, Context, Result};
use ark::musig::context::SigningInput;
use bitcoin::consensus::Encodable;
use emulator_connect::program::{
    EvaluationError, ProgramError, WasmEvaluator, MAX_FUNCTION_SLOTS, MAX_SIGNED_VIEW_BYTES,
    MAX_WITNESS_BYTES,
};
use sapio_base::program::{ProgramInstance, WasmVersion, MAX_PARAMETER_BYTES, MAX_PROGRAM_BYTES};
use sapio_wasm::host::{
    add_crypto_imports, add_crypto_imports_v2, bind_crypto, new_evaluator_store, INSTANCE_FUEL,
};
use sapio_wasm::{CRYPTO_NAMESPACE, CRYPTO_NAMESPACE_V2};
use std::ops::Range;
use wasmer::wasmparser::{Parser, Payload, TypeRef, ValType};
use wasmer::{Imports, Instance, Module, RuntimeError, Store, TypedFunction};
use wasmer_middlewares::metering::{get_remaining_points, MeteringPoints};

// Pointer/length pairs for program, parameters, signed view and witness.
type EvaluationArguments = (i32, i32, i32, i32, i32, i32, i32, i32);

/// Evaluate only the exact native context whose DEFAULT hash the nonce will bind.
/// This private function never receives a root secret or generates a signature.
pub(crate) fn authorize(
    registry: &[WasmEvaluator],
    program: &ProgramInstance,
    input: &SigningInput,
    witness: &[u8],
    message: &[u8; 32],
) -> Result<()> {
    sapio_psbt::validate_psbt(&input.psbt).map_err(ProgramError::Psbt)?;
    ensure!(input.sighash()? == *message,
        "evaluated transaction differs from the nested signing intent");
    let metadata = &input.psbt.inputs[input.input_index];
    if metadata.final_script_sig.is_some() || metadata.final_script_witness.is_some() {
        return Err(ProgramError::FinalizedInput.into());
    }
    // Ark's native signing context commits no annex. Previously a v2 annex
    // produced a different Sapio hash and failed the same intent comparison;
    // never expose annex bytes that the actual signature would not commit to.
    ensure!(sapio_psbt::annex::get(metadata)?.is_none(),
        "native Ark signing does not support an annex");
    let (module, selector, version) =
        if let Some(version) = program.evaluator().inline_wasm_version() {
            (program.program(), &[][..], version)
        } else {
            let evaluator = registry.iter().find(|entry| entry.id() == program.evaluator())
                .ok_or(ProgramError::UnknownEvaluator(program.evaluator()))?;
            (evaluator.module(), program.program(), evaluator.version())
        };
    if !evaluate(version, module, selector, program.parameters(), input, witness)
        .map_err(ProgramError::Evaluation)?
    {
        return Err(ProgramError::Rejected.into());
    }
    Ok(())
}

fn failure(error: impl std::fmt::Display) -> EvaluationError {
    EvaluationError(error.to_string())
}

fn check_module_bytes(module: &[u8]) -> Result<(), EvaluationError> {
    if module.len() > MAX_PROGRAM_BYTES {
        return Err(failure("WASM evaluator module exceeds 65536 bytes"));
    }
    if !module.starts_with(b"\0asm\x01\0\0\0") {
        return Err(failure("WASM evaluator requires a version-one binary module"));
    }
    Ok(())
}

fn check_compilation_budget(version: WasmVersion, module: &[u8]) -> Result<(), EvaluationError> {
    let mut function_types = Vec::new();
    let mut slots = 0u32;
    let mut add_slots = |count| -> Result<(), EvaluationError> {
        slots = slots.checked_add(count)
            .filter(|total| *total <= MAX_FUNCTION_SLOTS)
            .ok_or_else(|| failure("WASM evaluator exceeds 65536 function parameter/local slots"))?;
        Ok(())
    };
    for payload in Parser::new(0).parse_all(module) {
        match payload.map_err(failure)? {
            Payload::TypeSection(types) => {
                // Grow only for successfully decoded entries, never reserve
                // using an untrusted section count. The module byte cap
                // bounds this table and wasmparser bounds each function type.
                for ty in types.into_iter_err_on_gc_types() {
                    function_types.push(ty.map_err(failure)?);
                }
            }
            Payload::ImportSection(imports) => {
                for import in imports {
                    let import = import.map_err(failure)?;
                    let expected_params = match (import.module, import.name) {
                        (CRYPTO_NAMESPACE, "sha256" | "schnorr_verify") => 3,
                        (CRYPTO_NAMESPACE, "bip32_derive") => 4,
                        (CRYPTO_NAMESPACE_V2, "schnorr_verify" | "xonly_tweak_check")
                            if version == WasmVersion::V2 => 4,
                        _ => return Err(failure(
                            "unsupported WASM evaluator crypto import or namespace",
                        )),
                    };
                    let TypeRef::Func(index) = import.ty else {
                        return Err(failure("WASM evaluator imports must be crypto functions"));
                    };
                    let ty = function_types.get(index as usize)
                        .ok_or_else(|| failure("WASM evaluator import has an unknown type"))?;
                    if ty.params().len() != expected_params
                        || ty.params().iter().any(|ty| *ty != ValType::I32)
                        || ty.results() != [ValType::I32]
                    {
                        return Err(failure("WASM evaluator crypto import has an invalid signature"));
                    }
                }
            }
            Payload::FunctionSection(functions) => {
                for type_index in functions {
                    let ty = function_types.get(type_index.map_err(failure)? as usize)
                        .ok_or_else(|| failure("WASM evaluator function has an unknown type"))?;
                    // A shared type contributes once per defined function,
                    // because each body needs its own parameter slots.
                    add_slots(u32::try_from(ty.params().len()).map_err(failure)?)?;
                }
            }
            Payload::CodeSectionEntry(body) => {
                for local in body.get_locals_reader().map_err(failure)? {
                    add_slots(local.map_err(failure)?.0)?;
                }
            }
            Payload::StartSection { .. } => {
                return Err(failure("WASM evaluator modules cannot have a start function"));
            }
            _ => {}
        }
    }
    Ok(())
}

fn execution_error(
    store: &mut Store,
    instance: &Instance,
    operation: &str,
    error: RuntimeError,
) -> EvaluationError {
    if get_remaining_points(store, instance) == MeteringPoints::Exhausted {
        failure(format!(
            "WASM evaluator exhausted {INSTANCE_FUEL} fuel points during {operation}"
        ))
    } else {
        failure(format!("WASM evaluator {operation} failed: {error}"))
    }
}

fn evaluate(
    version: WasmVersion,
    module: &[u8],
    program: &[u8],
    parameters: &[u8],
    input: &SigningInput,
    witness: &[u8],
) -> Result<bool, EvaluationError> {
    check_module_bytes(module)?;
    check_compilation_budget(version, module)?;
    if program.len() > MAX_PROGRAM_BYTES
        || parameters.len() > MAX_PARAMETER_BYTES
        || witness.len() > MAX_WITNESS_BYTES
    {
        return Err(failure("WASM evaluator input exceeds its byte limit"));
    }
    let encoded_view = encode_view(version, input)?;
    let mut store = new_evaluator_store();
    let module = Module::new(&store, module).map_err(failure)?;
    let mut imports = Imports::new();
    let crypto = match version {
        WasmVersion::V1 => add_crypto_imports(&mut store, &mut imports),
        WasmVersion::V2 => add_crypto_imports_v2(&mut store, &mut imports),
    };
    let instance = Instance::new(&mut store, &module, &imports).map_err(failure)?;
    bind_crypto(&crypto, &mut store, &instance).map_err(failure)?;
    let memory = instance.exports.get_memory("memory").map_err(failure)?.clone();
    let (allocate_name, evaluate_name) = match version {
        WasmVersion::V1 => ("sapio_alloc_v1", "sapio_evaluate_v1"),
        WasmVersion::V2 => ("sapio_alloc_v2", "sapio_evaluate_v2"),
    };
    let allocate: TypedFunction<i32, i32> = instance.exports
        .get_typed_function(&store, allocate_name).map_err(failure)?;
    let evaluate: TypedFunction<EvaluationArguments, i32> = instance.exports
        .get_typed_function(&store, evaluate_name).map_err(failure)?;
    let inputs = [program, parameters, &encoded_view, witness];
    let mut ranges: [Range<u64>; 4] = std::array::from_fn(|_| 0..0);
    for (index, bytes) in inputs.iter().enumerate() {
        if bytes.is_empty() {
            continue;
        }
        let pointer = allocate.call(&mut store, bytes.len() as i32)
            .map_err(|error| execution_error(&mut store, &instance, allocate_name, error))?;
        let start = u64::from(pointer as u32);
        let end = start + bytes.len() as u64;
        if end > memory.view(&store).data_size() {
            return Err(failure("WASM evaluator allocation is outside linear memory"));
        }
        let range = start..end;
        if ranges[..index].iter().any(|previous| {
            !previous.is_empty() && range.start < previous.end && previous.start < range.end
        }) {
            return Err(failure("WASM evaluator input allocations overlap"));
        }
        ranges[index] = range;
    }
    // Allocate all regions before copying any input. An allocator cannot
    // rewrite an earlier input while allocating a later region.
    for (bytes, range) in inputs.iter().zip(&ranges) {
        memory.view(&store).write(range.start, bytes).map_err(failure)?;
    }
    let result = evaluate.call(
        &mut store,
        ranges[0].start as i32, inputs[0].len() as i32,
        ranges[1].start as i32, inputs[1].len() as i32,
        ranges[2].start as i32, inputs[2].len() as i32,
        ranges[3].start as i32, inputs[3].len() as i32,
    ).map_err(|error| execution_error(&mut store, &instance, evaluate_name, error))?;
    match result {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(failure("WASM evaluator must return exactly zero or one")),
    }
}

fn encode_view(version: WasmVersion, input: &SigningInput) -> Result<Vec<u8>, EvaluationError> {
    let tx = &input.psbt.unsigned_tx;
    // Native authentication requires witness_utxo for every input and checks
    // any non_witness_utxo against it. Borrow these same signed outputs without
    // copying transactions or creating a second prevout vector.
    let prevouts = || input.psbt.inputs.iter().map(|map| {
        map.witness_utxo.as_ref().expect("native context authenticated every prevout")
    });
    // Compute the bounded size before allocating or copying a script.
    let mut size = 20usize;
    let mut add = |amount: usize| -> Result<(), EvaluationError> {
        size = size.checked_add(amount)
            .filter(|size| *size <= MAX_SIGNED_VIEW_BYTES)
            .ok_or_else(|| failure("signed transaction view exceeds 1048576 bytes"))?;
        Ok(())
    };
    for prevout in prevouts() {
        add(52)?;
        add(prevout.script_pubkey.len())?;
    }
    for output in &tx.output {
        add(12)?;
        add(output.script_pubkey.len())?;
    }
    if version == WasmVersion::V2 {
        add(36)?; // Authenticated internal key and zero-length (absent) annex.
    }
    let input_count = u32::try_from(tx.input.len()).map_err(failure)?;
    let output_count = u32::try_from(tx.output.len()).map_err(failure)?;
    let input_index = u32::try_from(input.input_index).map_err(failure)?;
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(&tx.version.0.to_le_bytes());
    bytes.extend_from_slice(&tx.lock_time.to_consensus_u32().to_le_bytes());
    bytes.extend_from_slice(&input_index.to_le_bytes());
    bytes.extend_from_slice(&input_count.to_le_bytes());
    for (txin, prevout) in tx.input.iter().zip(prevouts()) {
        txin.previous_output.consensus_encode(&mut bytes)
            .expect("encoding an outpoint into a Vec cannot fail");
        bytes.extend_from_slice(&txin.sequence.to_consensus_u32().to_le_bytes());
        bytes.extend_from_slice(&prevout.value.to_sat().to_le_bytes());
        bytes.extend_from_slice(&(prevout.script_pubkey.len() as u32).to_le_bytes());
        bytes.extend_from_slice(prevout.script_pubkey.as_bytes());
    }
    bytes.extend_from_slice(&output_count.to_le_bytes());
    for output in &tx.output {
        bytes.extend_from_slice(&output.value.to_sat().to_le_bytes());
        bytes.extend_from_slice(&(output.script_pubkey.len() as u32).to_le_bytes());
        bytes.extend_from_slice(output.script_pubkey.as_bytes());
    }
    if version == WasmVersion::V2 {
        let internal = input.psbt.inputs[input.input_index].tap_internal_key
            .context("missing authenticated internal key").map_err(failure)?;
        bytes.extend_from_slice(&internal.serialize());
        bytes.extend_from_slice(&0u32.to_le_bytes());
    }
    debug_assert_eq!(bytes.len(), size);
    Ok(bytes)
}
