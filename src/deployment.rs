//! The program protocol and evaluator registry measured into the enclave image.

use anyhow::Result;
use bitcoin::bip32::Xpriv;
use emulator_connect::program::{ProgramOracle, WasmEvaluator};
use sapio_base::program::EvaluatorId;
use serde::{Deserialize, Serialize};

pub const IDENTITY_PROTOCOL: &str = "sapio-tee/program-oracle/1";
pub const MAX_CONNECTIONS: usize = 4;
pub const REQUEST_TIMEOUT_SECS: u64 = 30;
pub const PAY_AT_LEAST_SELECTOR: &[u8] = b"pay-at-least/v1";
/// Exact upstream artifact; provenance and digest are in evaluators/PROVENANCE.txt.
pub const PAY_AT_LEAST_WASM: &[u8] = include_bytes!("../evaluators/pay_at_least.wasm");

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InlineEvaluator {
    pub id: EvaluatorId,
    pub wasm_version: u8,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegisteredEvaluator {
    pub name: String,
    pub id: EvaluatorId,
    pub wasm_version: u8,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProgramProfile {
    pub protocol: String,
    pub inline_evaluators: Vec<InlineEvaluator>,
    pub registered_evaluators: Vec<RegisteredEvaluator>,
    pub max_connections: usize,
    pub request_timeout_secs: u64,
}

/// Produce public capabilities locally, without NSM, credentials, or a root key.
/// Verifiers must obtain this profile from an independently reviewed build.
pub fn program_profile() -> ProgramProfile {
    ProgramProfile {
        protocol: "SignProgramV1".into(),
        inline_evaluators: vec![
            InlineEvaluator {
                id: EvaluatorId::wasm(),
                wasm_version: 1,
            },
            InlineEvaluator {
                id: EvaluatorId::wasm_v2(),
                wasm_version: 2,
            },
        ],
        registered_evaluators: vec![RegisteredEvaluator {
            name: "pay-at-least/v1".into(),
            id: EvaluatorId::for_wasm(PAY_AT_LEAST_WASM),
            wasm_version: 1,
        }],
        max_connections: MAX_CONNECTIONS,
        request_timeout_secs: REQUEST_TIMEOUT_SECS,
    }
}

/// Fixed registry plus the upstream reserved inline WASM v1/v2 interpreters.
/// Adding a registered interpreter is a source/image change, not a setup option.
pub fn program_oracle(root: Xpriv) -> Result<ProgramOracle> {
    Ok(ProgramOracle::new(
        root,
        vec![WasmEvaluator::new(PAY_AT_LEAST_WASM.to_vec())?],
    )?)
}
