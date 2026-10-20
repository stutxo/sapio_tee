//! Optional native destination policy for Ark ownership proofs.
//!
//! The generic WASM evaluator only receives Bitcoin spend contexts. Native
//! `OwnershipProof::Offboard`, `Round` and `DelegatedRound` messages carry
//! destinations/output policies that a spend evaluator never sees, while the
//! corresponding forfeit is protocol-fixed. This envelope lets a program opt in
//! to an additional signer-side check before `S` releases its ownership partial.
//!
//! The envelope is part of the program's `parameters`, so it is committed by
//! `ProgramInstance::id()` and the program-derived key. A program that uses it
//! must be an inline WASM program able to tolerate the envelope (for example,
//! by ignoring parameters or parsing the trailing inner bytes). Legacy programs
//! whose parameters do not start with [`MAGIC`] are unchanged.
//!
//! Parameters layout:
//!
//! ```text
//! MAGIC || u32_le(document_len) || JSON(document) || inner_program_parameters
//! ```
//!
//! The document is deny-unknown-fields and versioned:
//!
//! ```json
//! {
//!   "version": 1,
//!   "offboard": ["<hex scriptPubKey>"],
//!   "arkoor": ["<hex VtxoPolicy>"],
//!   "round": ["<hex VtxoPolicy>"],
//!   "delegated_round": ["<hex VtxoPolicy>"],
//!   "status": true,
//!   "lightning_receive": false
//! }
//! ```
//!
//! Every value-moving variant is default-deny: an empty list rejects that
//! variant. `Status` and `LightningReceive` are explicit booleans. The check
//! covers destinations/outputs only; it is not a substitute for client-side
//! verification of the native request or for the spend evaluator.

use anyhow::{anyhow, ensure, Context, Result};
use ark::sapio::protocol::OwnershipProof;
use ark::{ProtocolEncoding, VtxoPolicy};
use bitcoin::hex::DisplayHex;
use bitcoin::ScriptBuf;
use serde::Deserialize;

/// Domain separator for the native ownership policy envelope.
pub const MAGIC: &[u8] = b"sapio-tee/native-ownership/v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    #[serde(default)]
    offboard: Vec<String>,
    #[serde(default)]
    arkoor: Vec<String>,
    #[serde(default)]
    round: Vec<String>,
    #[serde(default)]
    delegated_round: Vec<String>,
    #[serde(default)]
    status: bool,
    #[serde(default)]
    lightning_receive: bool,
}

/// Parsed, validated native ownership policy.
#[derive(Debug)]
pub struct NativePolicy {
    offboard: Vec<ScriptBuf>,
    arkoor: Vec<VtxoPolicy>,
    round: Vec<VtxoPolicy>,
    delegated_round: Vec<VtxoPolicy>,
    status: bool,
    lightning_receive: bool,
}

/// Parse the optional policy envelope from program parameters.
///
/// Returns `Ok(None)` for legacy programs. A parameter blob that starts with
/// [`MAGIC`] but is truncated, malformed, has an unknown version/field, or
/// contains an invalid script/policy fails closed.
pub fn parse(parameters: &[u8]) -> Result<Option<NativePolicy>> {
    let Some(rest) = parameters.strip_prefix(MAGIC) else {
        return Ok(None);
    };
    ensure!(
        rest.len() >= 4,
        "native ownership policy envelope is truncated"
    );
    let length = u32::from_le_bytes(rest[..4].try_into().expect("four bytes")) as usize;
    let end = 4usize
        .checked_add(length)
        .context("native ownership policy length overflows")?;
    ensure!(
        end <= rest.len(),
        "native ownership policy length exceeds the parameter blob"
    );
    let document: Document =
        serde_json::from_slice(&rest[4..end]).context("invalid native ownership policy JSON")?;
    ensure!(
        document.version == 1,
        "unsupported native ownership policy version"
    );

    let scripts = |values: &[String]| -> Result<Vec<ScriptBuf>> {
        values
            .iter()
            .map(|value| {
                ScriptBuf::from_hex(value)
                    .map_err(|error| anyhow!("invalid offboard destination script: {error}"))
            })
            .collect()
    };
    let policies = |values: &[String]| -> Result<Vec<VtxoPolicy>> {
        values
            .iter()
            .map(|value| {
                VtxoPolicy::deserialize_hex(value)
                    .map_err(|error| anyhow!("invalid VTXO output policy: {error}"))
            })
            .collect()
    };

    Ok(Some(NativePolicy {
        offboard: scripts(&document.offboard)?,
        arkoor: policies(&document.arkoor)?,
        round: policies(&document.round)?,
        delegated_round: policies(&document.delegated_round)?,
        status: document.status,
        lightning_receive: document.lightning_receive,
    }))
}

impl NativePolicy {
    /// Enforce the policy for one native ownership proof.
    pub fn enforce(&self, proof: &OwnershipProof) -> Result<()> {
        match proof {
            OwnershipProof::Status => ensure!(
                self.status,
                "native ownership policy does not allow status proofs"
            ),
            OwnershipProof::Arkoor { outputs } => {
                ensure!(
                    outputs
                        .iter()
                        .all(|output| self.arkoor.contains(&output.policy)),
                    "native ownership policy does not allow an arkoor output policy"
                );
            }
            OwnershipProof::Round { outputs, .. } => {
                ensure!(
                    outputs
                        .iter()
                        .all(|output| self.round.contains(&output.vtxo.policy)),
                    "native ownership policy does not allow a round output policy"
                );
            }
            OwnershipProof::DelegatedRound { outputs } => {
                ensure!(
                    outputs
                        .iter()
                        .all(|output| self.delegated_round.contains(&output.policy)),
                    "native ownership policy does not allow a delegated-round output policy"
                );
            }
            OwnershipProof::Offboard { request, .. } => {
                ensure!(
                    self.offboard.contains(&request.script_pubkey),
                    "native ownership policy does not allow the offboard destination"
                );
            }
            OwnershipProof::LightningReceive { .. } => ensure!(
                self.lightning_receive,
                "native ownership policy does not allow lightning receives"
            ),
        }
        Ok(())
    }
}

/// Serialize a document for tests and policy-construction helpers.
///
/// `inner` is appended after the document so a policy-aware program can keep
/// its own parameters. Clients constructing a program should use the same
/// layout as [`parse`].
pub fn encode(document: &[u8], inner: &[u8]) -> Vec<u8> {
    let length = u32::try_from(document.len()).expect("document length fits u32");
    let mut parameters = Vec::with_capacity(MAGIC.len() + 4 + document.len() + inner.len());
    parameters.extend_from_slice(MAGIC);
    parameters.extend_from_slice(&length.to_le_bytes());
    parameters.extend_from_slice(document);
    parameters.extend_from_slice(inner);
    parameters
}

/// Hex helper used by policy clients constructing the document.
pub fn script_hex(script: &ScriptBuf) -> String {
    script.as_bytes().to_lower_hex_string()
}

/// Hex helper used by policy clients constructing the document.
pub fn policy_hex(policy: &VtxoPolicy) -> String {
    policy.serialize_hex()
}
