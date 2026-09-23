//! The pinned v1 admission policy plus its unmodified evaluator engine.
use anyhow::{bail, ensure, Context, Result};
use emulator_connect::program::{MAX_FUNCTION_SLOTS, MAX_SIGNED_VIEW_BYTES, MAX_WITNESS_BYTES};
use sapio_base::program::{MAX_PARAMETER_BYTES, MAX_PROGRAM_BYTES};
use sapio_wasm::host::{add_crypto_imports, bind_crypto, new_evaluator_store, INSTANCE_FUEL};
use sapio_wasm::CRYPTO_NAMESPACE;
use std::ops::Range;
use std::time::{Duration, Instant};
use wasmer::wasmparser::{Parser, Payload, TypeRef, ValType};
use wasmer::{
    Engine, Function, FunctionEnv, FunctionEnvMut, Global, Imports, Instance, Module, RuntimeError,
    Store, TypedFunction, Value,
};
use wasmer_middlewares::metering::{get_remaining_points, set_remaining_points, MeteringPoints};

pub const DIAGNOSTIC_FUEL: u64 = 1_000_000_000;
// The pinned runtime keeps this constant private; new_evaluator_store enforces it.
const MAX_LINEAR_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
pub const PHASE_NAMES: [&str; 9] = [
    "abi_preflight",
    "proof_decoding_subgroup",
    "transaction_digest",
    "verification_key_decoding_validation",
    "public_input_scalar_multiplication",
    "pairing_preparation",
    "miller_loop",
    "final_exponentiation",
    "return_other",
];
const PROFILE_NAMESPACE: &str = "checkzkp_profile";
const PROFILE_MARK: &str = "mark";
type Arguments = (i32, i32, i32, i32, i32, i32, i32, i32);
type Groth16Arguments = (i32, i32, i32, i32, i32, i32);

#[derive(Clone, Copy)]
enum GuestAbi {
    ProgramV1,
    Groth16V1,
}

impl GuestAbi {
    fn allocator(self) -> &'static str {
        match self {
            Self::ProgramV1 => "sapio_alloc_v1",
            Self::Groth16V1 => "groth16_alloc_v1",
        }
    }
}

enum EntryPoint {
    Program(TypedFunction<Arguments, i32>),
    Groth16(TypedFunction<Groth16Arguments, i32>),
}

#[derive(Clone, Copy)]
pub enum Admission {
    Scored,
    LegacyDiagnostic,
    Profile,
}

impl Admission {
    fn profile(self) -> bool {
        matches!(self, Self::Profile)
    }
}

/// Mirror ctv_emulators::program::wasm::check_compilation_budget, which is private.
/// Use its public bounds and Wasmer's exact parser, not a second runtime policy.
/// Program-ABI controls permit SHA256 only; the generic proof ABI permits no
/// imports. Neither path can replace guest curve arithmetic with a host call.
fn admit(bytes: &[u8], admission: Admission, abi: GuestAbi) -> Result<()> {
    if matches!(admission, Admission::Scored) {
        ensure!(
            bytes.len() <= MAX_PROGRAM_BYTES,
            "module exceeds {MAX_PROGRAM_BYTES} bytes"
        );
    }
    ensure!(
        bytes.starts_with(b"\0asm\x01\0\0\0"),
        "expected a version-one binary WASM module"
    );
    let mut types = Vec::new();
    let mut slots = 0u32;
    let mut add_slots = |count| -> Result<()> {
        slots = slots
            .checked_add(count)
            .filter(|total| *total <= MAX_FUNCTION_SLOTS)
            .context("module exceeds function parameter/local slot limit")?;
        Ok(())
    };
    let mut markers = 0;
    for payload in Parser::new(0).parse_all(bytes) {
        match payload? {
            Payload::TypeSection(section) => {
                for ty in section.into_iter_err_on_gc_types() {
                    types.push(ty?);
                }
            }
            Payload::ImportSection(section) => {
                for import in section {
                    let import = import?;
                    ensure!(
                        matches!(abi, GuestAbi::ProgramV1),
                        "generic Groth16 verification permits no host imports"
                    );
                    let (parameters, returns_value) = match (import.module, import.name) {
                        (CRYPTO_NAMESPACE, "sha256") => (3, true),
                        (PROFILE_NAMESPACE, PROFILE_MARK) if admission.profile() => {
                            markers += 1;
                            (1, false)
                        }
                        _ => bail!("unsupported import {}::{}", import.module, import.name),
                    };
                    let TypeRef::Func(index) = import.ty else {
                        bail!("imports must be permitted host functions");
                    };
                    let ty = types
                        .get(index as usize)
                        .context("import has unknown function type")?;
                    ensure!(
                        ty.params().len() == parameters
                            && ty.params().iter().all(|ty| *ty == ValType::I32)
                            && if returns_value {
                                ty.results() == [ValType::I32]
                            } else {
                                ty.results().is_empty()
                            },
                        "invalid import signature for {}::{}",
                        import.module,
                        import.name
                    );
                }
            }
            Payload::FunctionSection(section) => {
                for index in section {
                    let ty = types
                        .get(index? as usize)
                        .context("function has unknown type")?;
                    add_slots(u32::try_from(ty.params().len())?)?;
                }
            }
            Payload::CodeSectionEntry(body) => {
                for local in body.get_locals_reader()? {
                    add_slots(local?.0)?;
                }
            }
            Payload::StartSection { .. } => {
                bail!("WASM evaluator modules cannot have a start function")
            }
            _ => {}
        }
    }
    if admission.profile() {
        ensure!(
            markers == 1,
            "profile module must import exactly one checkzkp_profile::mark"
        );
    }
    Ok(())
}

pub fn validate_inputs(parameters: &[u8], view: &[u8], witness: &[u8]) -> Result<()> {
    ensure!(
        parameters.len() <= MAX_PARAMETER_BYTES,
        "parameters exceed byte limit"
    );
    ensure!(
        view.len() <= MAX_SIGNED_VIEW_BYTES,
        "signed view exceeds byte limit"
    );
    ensure!(
        witness.len() <= MAX_WITNESS_BYTES,
        "witness exceeds byte limit"
    );
    Ok(())
}

pub struct Measurement {
    pub result: i32,
    pub fuel: u64,
    pub memory_bytes: u64,
    pub elapsed: Duration,
    pub phases: Option<[u64; 9]>,
    pub marker_calls: u64,
}

pub struct MeteredGuest {
    engine: Engine,
    module: Module,
    fuel: u64,
    profile: bool,
    abi: GuestAbi,
    pub compile_time: Duration,
}

impl MeteredGuest {
    pub fn new(bytes: &[u8], fuel: u64, admission: Admission) -> Result<Self> {
        Self::compile(bytes, fuel, admission, GuestAbi::ProgramV1)
    }

    /// Pure proof verification, not a Sapio signing predicate. Call
    /// `measure(verifying_key, public_inputs, proof)` with upstream encodings.
    pub fn for_groth16(bytes: &[u8], fuel: u64, admission: Admission) -> Result<Self> {
        ensure!(
            !admission.profile(),
            "generic Groth16 has no profiling import"
        );
        Self::compile(bytes, fuel, admission, GuestAbi::Groth16V1)
    }

    fn compile(bytes: &[u8], fuel: u64, admission: Admission, abi: GuestAbi) -> Result<Self> {
        ensure!(fuel > 0, "fuel must be finite and positive");
        admit(bytes, admission, abi)?;
        let store = new_evaluator_store();
        let started = Instant::now();
        let module = Module::new(&store, bytes).context("compiling admitted module")?;
        let compile_time = started.elapsed();
        Ok(Self {
            engine: store.engine().clone(),
            module,
            fuel,
            profile: admission.profile(),
            abi,
            compile_time,
        })
    }

    pub fn evaluate(
        &self,
        parameters: &[u8],
        view: &[u8],
        witness: &[u8],
        label: &str,
    ) -> Result<i32> {
        let measured = self
            .measure(parameters, view, witness)
            .with_context(|| format!("{label} failed to complete"))?;
        println!(
            "{label}: return {}; fuel={}; memory={} bytes; elapsed={:.3}s",
            measured.result,
            measured.fuel,
            measured.memory_bytes,
            measured.elapsed.as_secs_f64()
        );
        Ok(measured.result)
    }

    pub fn measure(&self, parameters: &[u8], view: &[u8], witness: &[u8]) -> Result<Measurement> {
        validate_inputs(parameters, view, witness)?;
        if matches!(self.abi, GuestAbi::Groth16V1) {
            ensure!(
                view.len() <= MAX_PARAMETER_BYTES,
                "public inputs exceed byte limit"
            );
        }
        // Reuse only the compiled module and the exact engine from new_evaluator_store.
        // Dropping each fresh Store releases all its instance objects and linear memory.
        let mut store = Store::new(self.engine.clone());
        let mut imports = Imports::new();
        let crypto = matches!(self.abi, GuestAbi::ProgramV1)
            .then(|| add_crypto_imports(&mut store, &mut imports));
        let profile = self.profile.then(|| {
            let env = FunctionEnv::new(&mut store, PhaseTracker::new(self.fuel));
            imports.define(
                PROFILE_NAMESPACE,
                PROFILE_MARK,
                Function::new_typed_with_env(&mut store, &env, mark),
            );
            env
        });
        let instance =
            Instance::new(&mut store, &self.module, &imports).context("instantiating module")?;
        if let Some(crypto) = crypto {
            bind_crypto(&crypto, &mut store, &instance)?;
        }
        // The only allowance change is before any guest call, with start sections forbidden.
        // No callback, case retry, allocation, or verification ever refunds fuel.
        if self.fuel != INSTANCE_FUEL {
            set_remaining_points(&mut store, &instance, self.fuel);
        }
        if let Some(profile) = &profile {
            profile.as_mut(&mut store).globals = Some((
                instance
                    .exports
                    .get_global("wasmer_metering_remaining_points")?
                    .clone(),
                instance
                    .exports
                    .get_global("wasmer_metering_points_exhausted")?
                    .clone(),
            ));
        }
        let memory = instance.exports.get_memory("memory")?.clone();
        let alloc: TypedFunction<i32, i32> = instance
            .exports
            .get_typed_function(&store, self.abi.allocator())?;
        let evaluate = match self.abi {
            GuestAbi::ProgramV1 => EntryPoint::Program(
                instance
                    .exports
                    .get_typed_function(&store, "sapio_evaluate_v1")?,
            ),
            GuestAbi::Groth16V1 => EntryPoint::Groth16(
                instance
                    .exports
                    .get_typed_function(&store, "groth16_verify_v1")?,
            ),
        };
        ensure!(
            memory.view(&store).data_size() <= MAX_LINEAR_MEMORY_BYTES,
            "linear memory exceeds runtime limit"
        );
        let started = Instant::now();
        // ProgramV1: parameters/view/witness. Groth16V1: key/public inputs/proof.
        let inputs = [parameters, view, witness];
        let mut ranges: [Range<u64>; 3] = std::array::from_fn(|_| 0..0);
        for (index, bytes) in inputs.iter().enumerate() {
            if bytes.is_empty() {
                continue;
            }
            let result = alloc.call(&mut store, bytes.len() as i32);
            remaining(&mut store, &instance, self.fuel)?;
            let pointer = result.with_context(|| format!("{} trapped", self.abi.allocator()))?;
            if matches!(self.abi, GuestAbi::Groth16V1) {
                ensure!(pointer != 0, "groth16_alloc_v1 failed");
            }
            let start = u64::from(pointer as u32);
            let end = start
                .checked_add(bytes.len() as u64)
                .context("allocation range overflow")?;
            ensure!(
                end <= memory.view(&store).data_size(),
                "allocation outside linear memory"
            );
            let range = start..end;
            ensure!(
                !ranges[..index].iter().any(|previous| {
                    !previous.is_empty() && range.start < previous.end && previous.start < range.end
                }),
                "input allocations overlap"
            );
            ranges[index] = range;
        }
        // As upstream, allocate everything before copying, preventing allocators from
        // rewriting earlier input buffers while allocating subsequent buffers.
        for (bytes, range) in inputs.iter().zip(&ranges) {
            memory.view(&store).write(range.start, bytes)?;
        }
        let result = match evaluate {
            EntryPoint::Program(evaluate) => evaluate.call(
                &mut store,
                0,
                0,
                ranges[0].start as i32,
                parameters.len() as i32,
                ranges[1].start as i32,
                view.len() as i32,
                ranges[2].start as i32,
                witness.len() as i32,
            ),
            EntryPoint::Groth16(verify) => verify.call(
                &mut store,
                ranges[0].start as i32,
                parameters.len() as i32,
                ranges[2].start as i32,
                witness.len() as i32,
                ranges[1].start as i32,
                view.len() as i32,
            ),
        };
        let elapsed = started.elapsed();
        let left = remaining(&mut store, &instance, self.fuel)?;
        let result = result.context("guest evaluation trapped")?;
        let memory_bytes = memory.view(&store).data_size();
        ensure!(
            memory_bytes <= MAX_LINEAR_MEMORY_BYTES,
            "linear memory exceeds runtime limit"
        );
        let (phases, marker_calls) = if let Some(profile) = profile {
            let tracker = profile.as_mut(&mut store);
            tracker.finish(left)?;
            (Some(tracker.totals), tracker.calls)
        } else {
            (None, 0)
        };
        Ok(Measurement {
            result,
            fuel: self.fuel - left,
            memory_bytes,
            elapsed,
            phases,
            marker_calls,
        })
    }
}

fn remaining(store: &mut Store, instance: &Instance, fuel: u64) -> Result<u64> {
    match get_remaining_points(store, instance) {
        MeteringPoints::Remaining(left) => {
            ensure!(left <= fuel, "remaining fuel exceeds initial allowance");
            Ok(left)
        }
        MeteringPoints::Exhausted => {
            bail!("WASM exhausted its finite {fuel}-unit allowance; exhaustion is not rejection")
        }
    }
}

struct PhaseTracker {
    globals: Option<(Global, Global)>,
    phase: usize,
    last_remaining: u64,
    totals: [u64; 9],
    seen: [bool; 9],
    calls: u64,
}

impl PhaseTracker {
    fn new(fuel: u64) -> Self {
        let mut seen = [false; 9];
        seen[0] = true;
        Self {
            globals: None,
            phase: 0,
            last_remaining: fuel,
            totals: [0; 9],
            seen,
            calls: 0,
        }
    }

    fn account(&mut self, left: u64) -> Result<()> {
        let delta = self
            .last_remaining
            .checked_sub(left)
            .context("profile fuel increased")?;
        self.totals[self.phase] = self.totals[self.phase]
            .checked_add(delta)
            .context("profile fuel overflow")?;
        self.last_remaining = left;
        Ok(())
    }

    fn finish(&mut self, left: u64) -> Result<()> {
        self.account(left)?;
        ensure!(
            self.seen.iter().all(|seen| *seen),
            "profile did not visit every required phase"
        );
        ensure!(
            self.phase == 8,
            "profile did not finish in return/other phase"
        );
        Ok(())
    }
}

fn mark(mut env: FunctionEnvMut<'_, PhaseTracker>, phase: i32) -> Result<(), RuntimeError> {
    let fail = |message: &str| RuntimeError::new(message);
    let phase = usize::try_from(phase).map_err(|_| fail("negative profile phase"))?;
    if phase >= PHASE_NAMES.len() {
        return Err(fail("unknown profile phase"));
    }
    let (remaining, exhausted) = env
        .data()
        .globals
        .clone()
        .ok_or_else(|| fail("unbound profile marker"))?;
    let Value::I32(exhausted) = exhausted.get(&mut env) else {
        return Err(fail("invalid profile exhausted global"));
    };
    let Value::I64(left) = remaining.get(&mut env) else {
        return Err(fail("invalid profile remaining global"));
    };
    if exhausted != 0 {
        return Err(fail("profile fuel exhausted"));
    }
    // Only read the engine's existing globals. Marker instructions are charged by
    // ordinary middleware and remain in the phase totals; no host refund exists.
    let tracker = env.data_mut();
    tracker
        .account(left as u64)
        .map_err(|error| RuntimeError::new(error.to_string()))?;
    tracker.phase = phase;
    tracker.seen[phase] = true;
    tracker.calls += 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_allocator_failure_is_not_a_malformed_proof() -> Result<()> {
        let module = wasmer::wat2wasm(
            br#"(module
                (memory (export "memory") 1 1024)
                (func (export "groth16_alloc_v1") (param i32) (result i32)
                    (i32.const 0))
                (func (export "groth16_verify_v1")
                    (param i32 i32 i32 i32 i32 i32) (result i32)
                    (i32.const -1))
            )"#,
        )?;
        let guest = MeteredGuest::for_groth16(&module, INSTANCE_FUEL, Admission::Scored)?;
        // One nonempty buffer: overlapping allocations cannot mask a null result.
        assert!(guest.measure(&[], &[0; 8], &[]).is_err());
        Ok(())
    }
}
