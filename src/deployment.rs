//! The program protocol and evaluator registry measured into the enclave image.

use anyhow::Result;
use bitcoin::bip32::Xpriv;
use emulator_connect::program::{ProgramOracle, WasmEvaluator};
use sapio_base::program::{EvaluatorId, WasmVersion};
use serde::{Deserialize, Serialize};

use crate::ark_signer::{MAX_PENDING_SESSIONS, MAX_SESSIONS_PER_USER, SESSION_LIFETIME_SECS};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArkSigningProfile {
    pub protocol: String,
    pub max_pending_sessions: usize,
    pub max_sessions_per_user: usize,
    pub session_lifetime_secs: u64,
    /// The signer enforces the optional native ownership policy envelope
    /// before releasing an Ark Ownership partial.
    pub native_ownership_policy: bool,
}

pub const IDENTITY_PROTOCOL: &str = "sapio-tee/program-oracle/1";
pub const MAX_CONNECTIONS: usize = 4;
pub const REQUEST_TIMEOUT_SECS: u64 = 30;
pub const PAY_AT_LEAST_SELECTOR: &[u8] = b"pay-at-least/v1";
/// Exact upstream artifact; provenance and digest are in evaluators/PROVENANCE.txt.
pub const PAY_AT_LEAST_WASM: &[u8] = include_bytes!("../evaluators/pay_at_least.wasm");

// One measured definition feeds the advertised profile and both execution
// paths; neither service can inject a different runtime registry at setup.
const REGISTERED: &[(&str, WasmVersion, &[u8])] = &[
    ("pay-at-least/v1", WasmVersion::V1, PAY_AT_LEAST_WASM),
];

pub(crate) fn evaluators() -> Result<Vec<WasmEvaluator>> {
    REGISTERED.iter().map(|(_, version, module)| {
        Ok(WasmEvaluator::with_version(*version, module.to_vec())?)
    }).collect()
}

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
    pub ark_signing: ArkSigningProfile,
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
        registered_evaluators: REGISTERED.iter().map(|(name, version, module)| {
            RegisteredEvaluator {
                name: (*name).into(),
                id: EvaluatorId::for_wasm_version(module, *version),
                wasm_version: match version {
                    WasmVersion::V1 => 1,
                    WasmVersion::V2 => 2,
                },
            }
        }).collect(),
        max_connections: MAX_CONNECTIONS,
        request_timeout_secs: REQUEST_TIMEOUT_SECS,
        ark_signing: ArkSigningProfile {
            protocol: ark::sapio::protocol::SIGNING_PROTOCOL.into(),
            max_pending_sessions: MAX_PENDING_SESSIONS,
            max_sessions_per_user: MAX_SESSIONS_PER_USER,
            session_lifetime_secs: SESSION_LIFETIME_SECS,
            native_ownership_policy: true,
        },
    }
}

/// Fixed registry plus the upstream reserved inline WASM v1/v2 interpreters.
/// Adding a registered interpreter is a source/image change, not a setup option.
pub fn program_oracle(root: Xpriv) -> Result<ProgramOracle> {
    Ok(ProgramOracle::new(root, evaluators()?)?)
}
