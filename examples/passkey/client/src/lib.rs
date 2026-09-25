//! Deterministic, public-only wallet core. No network, randomness or host imports.
mod context;
#[path = "../../contract.rs"]
pub mod contract;
mod core;
pub mod wire;

use anyhow::{anyhow, ensure, Result};
pub use context::{Identity, InlineEvaluator, ProgramProfile, RegisteredEvaluator, WalletContext};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const CAPACITY: usize = 1_048_576;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Call {
    pub operation: String,
    pub context: WalletContext,
    pub body: Value,
}

/// The same operation dispatcher used by native tooling and browser WASM.
pub fn call(input: Call) -> Result<Value> {
    let wallet = input.context.validate()?;
    core::dispatch(&wallet, &input.operation, input.body)
}

/// Consume exactly one bounded JSON document and return the fixed result envelope.
pub fn execute(input: &[u8]) -> Vec<u8> {
    let result = (|| -> Result<Value> {
        ensure!(
            !input.is_empty() && input.len() <= CAPACITY,
            "invalid wallet input length"
        );
        let input: Call =
            serde_json::from_slice(input).map_err(|_| anyhow!("invalid wallet input JSON"))?;
        call(input)
    })();
    let envelope = match result {
        Ok(value) => json!({"ok": value}),
        Err(error) => json!({"error": format!("{error:#}")}),
    };
    match serde_json::to_vec(&envelope) {
        Ok(bytes) if bytes.len() <= CAPACITY => bytes,
        _ => b"{\"error\":\"wallet output exceeds capacity\"}".to_vec(),
    }
}

#[cfg(target_arch = "wasm32")]
mod abi {
    use super::CAPACITY;

    static mut INPUT: [u8; CAPACITY] = [0; CAPACITY];
    static mut OUTPUT: [u8; CAPACITY] = [0; CAPACITY];

    #[no_mangle]
    pub extern "C" fn wallet_input() -> u32 {
        std::ptr::addr_of_mut!(INPUT).cast::<u8>() as u32
    }

    #[no_mangle]
    pub extern "C" fn wallet_input_capacity() -> u32 {
        CAPACITY as u32
    }

    #[no_mangle]
    pub extern "C" fn wallet_output() -> u32 {
        std::ptr::addr_of_mut!(OUTPUT).cast::<u8>() as u32
    }

    #[no_mangle]
    pub extern "C" fn wallet_output_capacity() -> u32 {
        CAPACITY as u32
    }

    #[no_mangle]
    pub extern "C" fn wallet_execute(input_length: u32) -> u32 {
        let bytes = if input_length as usize > CAPACITY {
            b"{\"error\":\"invalid wallet input length\"}".to_vec()
        } else {
            // The host writes only the exported fixed input buffer, and a fresh
            // single-threaded instance is used for every operation.
            let input = unsafe {
                std::slice::from_raw_parts(
                    std::ptr::addr_of!(INPUT).cast::<u8>(),
                    input_length as usize,
                )
            };
            super::execute(input)
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                std::ptr::addr_of_mut!(OUTPUT).cast::<u8>(),
                bytes.len(),
            );
        }
        bytes.len() as u32
    }
}
