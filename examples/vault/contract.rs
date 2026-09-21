//! A single, independently sufficient inline-WASM spending policy.
//!
//! Anyone can request a full sweep to the committed destination within the fee
//! cap. This is not an owner-authorized, delayed or recoverable vault.

// sapio::contract::CompilationError is 192 bytes and its signatures are fixed
// by the upstream contract API; the large Err variant is not ours to shrink.
#![allow(clippy::result_large_err)]

use anyhow::{Context as _, Result};
use bitcoin::bip32::Xpub;
use bitcoin::Script;
use sapio_base::policy::ScriptPolicy;
use sapio_base::program::{EmulatedProgram, ProgramInstance};

/// Deliberately use the inline v1 evaluator, not an operator-registered ID.
const VAULT_WASM: &[u8] = include_bytes!("vault.wasm");

/// Commit the module and max_fee:u64LE || script_len:u32LE || script bytes.
/// The inline guest receives an empty program argument; no witness is needed.
pub fn instance(max_fee_satoshis: u64, destination: &Script) -> Result<ProgramInstance> {
    let script_len = u32::try_from(destination.len()).context("destination script too large")?;
    let mut parameters = Vec::with_capacity(12 + destination.len());
    parameters.extend_from_slice(&max_fee_satoshis.to_le_bytes());
    parameters.extend_from_slice(&script_len.to_le_bytes());
    parameters.extend_from_slice(destination.as_bytes());
    Ok(ProgramInstance::wasm(VAULT_WASM.to_vec(), parameters)?)
}

pub struct SafeWithdrawal {
    pub(super) emulation: EmulatedProgram,
}

#[sapio::contract]
impl SafeWithdrawal {
    /// The independently verified public oracle root is part of the contract.
    pub fn new(max_fee_satoshis: u64, destination: &Script, root: Xpub) -> Result<Self> {
        Ok(Self {
            emulation: EmulatedProgram::new(instance(max_fee_satoshis, destination)?, root)?,
        })
    }

    #[spend]
    fn safe_withdrawal(&self) -> ScriptPolicy {
        self.emulation.clone().into()
    }
}
