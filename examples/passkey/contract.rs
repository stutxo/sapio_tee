//! Client-side encoding for the inline v2 passkey policy.
//!
//! Funding commits to one two-key MuSig2 recovery leaf. Normal spending still
//! requires passkey authorization; recovery does not require the enclave.

use anyhow::{ensure, Context, Result};
use bitcoin::bip32::Xpub;
use bitcoin::blockdata::opcodes::all::OP_CHECKSIG;
use bitcoin::blockdata::script::Builder;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TapNodeHash};
use bitcoin::{Address, Network, ScriptBuf};
use sapio_base::program::{program_derivation_path, ProgramInstance, MAX_PROGRAM_ROOT_DEPTH};

pub const WASM: &[u8] = include_bytes!("passkey.wasm");
pub const CHALLENGE_DOMAIN: &[u8] = b"sapio-passkey/v2\0";
pub const MAX_CLIENT_DATA: usize = 4096;

pub fn hash(bytes: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(bytes).to_byte_array()
}

pub struct Recovery {
    pub public_keys: [[u8; 33]; 2],
    pub aggregate_key: XOnlyPublicKey,
    pub script: ScriptBuf,
    pub leaf_hash: TapLeafHash,
}

pub fn recovery(keys: &[[u8; 33]; 2]) -> Result<Recovery> {
    let mut public_keys = *keys;
    public_keys.sort_unstable();
    let aggregate = passkey_recovery::aggregate_keys(&public_keys)
        .context("invalid or duplicate recovery public keys")?;
    let aggregate_key =
        XOnlyPublicKey::from_slice(&aggregate).context("invalid recovery aggregate key")?;
    let script = Builder::new()
        .push_slice(aggregate_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
    Ok(Recovery {
        public_keys,
        aggregate_key,
        script,
        leaf_hash,
    })
}

/// The passkey, recovery root and WebAuthn context are immutable funded policy data.
pub fn instance(
    network: Network,
    rp_id: &str,
    origin: &str,
    public_key: &[u8],
    recovery: &Recovery,
) -> Result<ProgramInstance> {
    ensure!(
        public_key.len() == 33 && matches!(public_key[0], 2 | 3),
        "expected a compressed 33-byte ES256 public key"
    );
    p256::PublicKey::from_sec1_bytes(public_key)
        .map_err(|_| anyhow::anyhow!("invalid P-256 public key"))?;
    ensure!(
        !rp_id.is_empty() && rp_id.len() <= 253 && rp_id.is_ascii(),
        "invalid RP ID"
    );
    ensure!(
        !origin.is_empty() && origin.len() <= 256,
        "invalid origin length"
    );
    let mut parameters = Vec::with_capacity(137 + origin.len());
    parameters.extend_from_slice(b"SPK2");
    parameters.extend_from_slice(
        &bitcoin::blockdata::constants::genesis_block(network)
            .block_hash()
            .to_byte_array(),
    );
    parameters.extend_from_slice(public_key);
    parameters.extend_from_slice(recovery.leaf_hash.as_byte_array());
    parameters.extend_from_slice(&hash(rp_id.as_bytes()));
    parameters.extend_from_slice(&(origin.len() as u32).to_le_bytes());
    parameters.extend_from_slice(origin.as_bytes());
    Ok(ProgramInstance::wasm_v2(WASM.to_vec(), parameters)?)
}

pub fn recovery_root(instance: &ProgramInstance) -> Result<TapNodeHash> {
    let parameters = instance.parameters();
    ensure!(
        parameters.len() >= 137 && &parameters[..4] == b"SPK2",
        "invalid SPK2 policy"
    );
    let origin_len = u32::from_le_bytes(parameters[133..137].try_into()?) as usize;
    ensure!(
        (1..=256).contains(&origin_len) && parameters.len() == 137 + origin_len,
        "invalid SPK2 origin length"
    );
    std::str::from_utf8(&parameters[137..]).context("invalid SPK2 origin")?;
    Ok(TapNodeHash::from_byte_array(
        parameters[69..101].try_into()?,
    ))
}

/// Use Sapio's exact public derivation path without its WASM host ABI.
pub fn derive_public_key(instance: &ProgramInstance, root: &Xpub) -> Result<XOnlyPublicKey> {
    ensure!(
        root.depth <= MAX_PROGRAM_ROOT_DEPTH,
        "program root depth exceeds derivation limit"
    );
    Ok(root
        .derive_pub(
            &Secp256k1::verification_only(),
            &program_derivation_path(instance.id()),
        )?
        .public_key
        .x_only_public_key()
        .0)
}

pub fn address(instance: &ProgramInstance, root: &Xpub, network: Network) -> Result<Address> {
    let key = derive_public_key(instance, root)?;
    Ok(Address::p2tr(
        &Secp256k1::verification_only(),
        key,
        Some(recovery_root(instance)?),
        network,
    ))
}

/// Exact pinned Sapio v2 projection, with the example's no-annex restriction.
///
/// Never hash PSBT JSON, txid alone, CTV, or TemplateHash as a replacement: those
/// representations do not bind the same inputs, amounts and signature context.
pub fn signed_view(psbt: &Psbt, input_index: u32) -> Result<Vec<u8>> {
    let transaction = &psbt.unsigned_tx;
    ensure!(
        transaction.input.len() == psbt.inputs.len(),
        "PSBT input count mismatch"
    );
    let selected = psbt
        .inputs
        .get(input_index as usize)
        .context("invalid selected input")?;
    let internal_key = selected
        .tap_internal_key
        .context("missing Taproot internal key")?;
    // Both paths use this complete transaction projection without an annex.
    ensure!(
        selected.proprietary.is_empty(),
        "annex/proprietary input fields unsupported"
    );
    let mut size = 56usize;
    for input in &psbt.inputs {
        let prevout = input
            .witness_utxo
            .as_ref()
            .context("missing input prevout")?;
        size = size
            .checked_add(52 + prevout.script_pubkey.len())
            .context("view size overflow")?;
    }
    for output in &transaction.output {
        size = size
            .checked_add(12 + output.script_pubkey.len())
            .context("view size overflow")?;
    }
    ensure!(size <= 1_048_576, "signed view exceeds 1 MiB");
    let mut view = Vec::with_capacity(size);
    view.extend_from_slice(&transaction.version.0.to_le_bytes());
    view.extend_from_slice(&transaction.lock_time.to_consensus_u32().to_le_bytes());
    view.extend_from_slice(&input_index.to_le_bytes());
    view.extend_from_slice(&(transaction.input.len() as u32).to_le_bytes());
    for (input, metadata) in transaction.input.iter().zip(&psbt.inputs) {
        let prevout = metadata
            .witness_utxo
            .as_ref()
            .context("missing input prevout")?;
        input.previous_output.consensus_encode(&mut view)?;
        view.extend_from_slice(&input.sequence.0.to_le_bytes());
        view.extend_from_slice(&prevout.value.to_sat().to_le_bytes());
        view.extend_from_slice(&(prevout.script_pubkey.len() as u32).to_le_bytes());
        view.extend_from_slice(prevout.script_pubkey.as_bytes());
    }
    view.extend_from_slice(&(transaction.output.len() as u32).to_le_bytes());
    for output in &transaction.output {
        view.extend_from_slice(&output.value.to_sat().to_le_bytes());
        view.extend_from_slice(&(output.script_pubkey.len() as u32).to_le_bytes());
        view.extend_from_slice(output.script_pubkey.as_bytes());
    }
    view.extend_from_slice(&internal_key.serialize());
    view.extend_from_slice(&0u32.to_le_bytes());
    Ok(view)
}

pub fn challenge(parameters: &[u8], view: &[u8], nonce: &[u8; 32]) -> [u8; 32] {
    let mut message = [0; CHALLENGE_DOMAIN.len() + 96];
    message[..CHALLENGE_DOMAIN.len()].copy_from_slice(CHALLENGE_DOMAIN);
    message[CHALLENGE_DOMAIN.len()..CHALLENGE_DOMAIN.len() + 32].copy_from_slice(&hash(parameters));
    message[CHALLENGE_DOMAIN.len() + 32..CHALLENGE_DOMAIN.len() + 64].copy_from_slice(&hash(view));
    message[CHALLENGE_DOMAIN.len() + 64..].copy_from_slice(nonce);
    hash(&message)
}

pub fn witness(
    nonce: &[u8; 32],
    auth_data: &[u8],
    client_data: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>> {
    ensure!(
        auth_data.len() == 37,
        "authenticator extensions/attestation data unsupported"
    );
    ensure!(
        !client_data.is_empty() && client_data.len() <= MAX_CLIENT_DATA,
        "invalid clientDataJSON length"
    );
    ensure!(
        (8..=72).contains(&signature.len()),
        "invalid ES256 DER signature length"
    );
    let mut bytes = Vec::with_capacity(44 + auth_data.len() + client_data.len() + signature.len());
    bytes.extend_from_slice(nonce);
    for field in [auth_data, client_data, signature] {
        bytes.extend_from_slice(&(field.len() as u32).to_le_bytes());
        bytes.extend_from_slice(field);
    }
    Ok(bytes)
}

pub fn funding_script(key: XOnlyPublicKey, root: TapNodeHash) -> ScriptBuf {
    ScriptBuf::new_p2tr(&Secp256k1::verification_only(), key, Some(root))
}
