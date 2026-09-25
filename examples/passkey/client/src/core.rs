//! Public wallet operations shared by the browser WASM and native driver.
use crate::{
    context::Wallet,
    contract,
    wire::{OracleRequest, OracleResponse, SigningRequest, WirePsbt, MAX_PSBT},
};
use anyhow::{anyhow, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{schnorr, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootBuilder};
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};
use miniscript::psbt::PsbtExt;
use sapio_base::program::{EvaluatorId, ProgramInstance, ProgramSpendPath};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::str::FromStr;

const MAX_MONEY: u64 = 2_100_000_000_000_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletInput {
    public_key: String,
    recovery_keys: [String; 2],
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Funding {
    txid: Txid,
    vout: u32,
    value_sats: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareInput {
    public_key: String,
    recovery_keys: [String; 2],
    funding: Funding,
    recipient: String,
    amount_sats: u64,
    fee_sats: u64,
    path: SpendPath,
    nonce: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignInput {
    public_key: String,
    recovery_keys: [String; 2],
    psbt: String,
    nonce: String,
    authenticator_data: String,
    client_data_json: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryInput {
    public_key: String,
    recovery_keys: [String; 2],
    psbt: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum SpendPath {
    Passkey,
    Recovery,
}

fn decode_hex(value: &str, maximum: usize, name: &str) -> Result<Vec<u8>> {
    ensure!(value.len() <= maximum * 2, "{name} exceeds byte limit");
    hex::decode(value).with_context(|| format!("invalid {name} hex"))
}

fn policy(
    app: &Wallet<'_>,
    public_key: &str,
    recovery_keys: &[String; 2],
) -> Result<(ProgramInstance, contract::Recovery)> {
    let key = decode_hex(public_key, 33, "public key")?;
    let mut keys = [[0; 33]; 2];
    for (target, encoded) in keys.iter_mut().zip(recovery_keys) {
        *target = decode_hex(encoded, 33, "recovery public key")?
            .try_into()
            .map_err(|_| anyhow!("recovery public keys must be compressed 33-byte SEC1 points"))?;
    }
    let recovery = contract::recovery(&keys)?;
    let instance = contract::instance(app.network, app.rp_id, app.origin, &key, &recovery)?;
    Ok((instance, recovery))
}

fn recovery_control(
    key: bitcoin::XOnlyPublicKey,
    recovery: &contract::Recovery,
) -> Result<ControlBlock> {
    let spend = TaprootBuilder::new()
        .add_leaf(0, recovery.script.clone())?
        .finalize(&Secp256k1::verification_only(), key)
        .map_err(|_| anyhow!("invalid single-leaf recovery tree"))?;
    spend
        .control_block(&(recovery.script.clone(), LeafVersion::TapScript))
        .context("missing recovery control block")
}

fn recovery_descriptor(
    key: bitcoin::XOnlyPublicKey,
    recovery: &contract::Recovery,
) -> Result<Value> {
    Ok(json!({
        "public_keys": recovery.public_keys.map(hex::encode),
        "aggregate_key": recovery.aggregate_key.to_string(),
        "leaf_script": hex::encode(recovery.script.as_bytes()),
        "leaf_hash": hex::encode(recovery.leaf_hash.to_byte_array()),
        "control_block": hex::encode(recovery_control(key, recovery)?.serialize()),
    }))
}

fn attach_recovery(psbt: &mut Psbt, recovery: &contract::Recovery) -> Result<()> {
    let key = psbt.inputs[0]
        .tap_internal_key
        .context("missing wallet internal key")?;
    psbt.inputs[0].tap_scripts.insert(
        recovery_control(key, recovery)?,
        (recovery.script.clone(), LeafVersion::TapScript),
    );
    Ok(())
}

fn recovery_sighash(psbt: &Psbt, recovery: &contract::Recovery) -> Result<[u8; 32]> {
    let prevout = psbt.inputs[0]
        .witness_utxo
        .as_ref()
        .context("missing funding prevout")?;
    Ok(SighashCache::new(&psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout]),
            recovery.leaf_hash,
            TapSighashType::All,
        )?
        .to_byte_array())
}

fn checked_sats(value: u64, name: &str) -> Result<Amount> {
    ensure!(
        (1..=MAX_MONEY).contains(&value),
        "{name} must be positive integer satoshis within MAX_MONEY"
    );
    Ok(Amount::from_sat(value))
}

fn native_recipient(address: &str, network: Network) -> Result<Address> {
    let address = Address::from_str(address)
        .context("invalid recipient address")?
        .require_network(network)
        .context("recipient is for a different Bitcoin network")?;
    let script = address.script_pubkey();
    ensure!(
        script.is_p2wpkh() || script.is_p2wsh() || script.is_p2tr(),
        "example supports native SegWit v0/v1 recipients only"
    );
    Ok(address)
}

fn synthetic_funding(script_pubkey: ScriptBuf) -> Funding {
    let transaction = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey,
        }],
    };
    Funding {
        txid: transaction.compute_txid(),
        vout: 0,
        value_sats: 100_000,
    }
}

fn prepare_transaction(
    app: &Wallet<'_>,
    input: &PrepareInput,
) -> Result<(ProgramInstance, Psbt, Value, contract::Recovery)> {
    let (instance, recovery) = policy(app, &input.public_key, &input.recovery_keys)?;
    let key = contract::derive_public_key(&instance, app.root)?;
    let address = Address::from_script(
        &contract::funding_script(key, contract::recovery_root(&instance)?),
        app.network,
    )?;
    let funding_amount = checked_sats(input.funding.value_sats, "funding value")?;
    let amount = checked_sats(input.amount_sats, "payment amount")?;
    checked_sats(input.fee_sats, "fee")?;
    ensure!(
        input.funding.txid != Txid::all_zeros(),
        "null funding txid is not a UTXO"
    );
    let recipient = native_recipient(&input.recipient, app.network)?;
    let recipient_script = recipient.script_pubkey();
    ensure!(
        amount >= recipient_script.minimal_non_dust(),
        "recipient output is below its dust threshold"
    );
    let change = input
        .funding
        .value_sats
        .checked_sub(input.amount_sats)
        .and_then(|remaining| remaining.checked_sub(input.fee_sats))
        .context("payment plus fee exceeds the supplied UTXO value")?;
    ensure!(
        change == 0 || Amount::from_sat(change) >= address.script_pubkey().minimal_non_dust(),
        "change is dust; adjust amount or explicitly increase the fee"
    );
    let mut outputs = vec![TxOut {
        value: amount,
        script_pubkey: recipient_script,
    }];
    if change > 0 {
        outputs.push(TxOut {
            value: Amount::from_sat(change),
            script_pubkey: address.script_pubkey(),
        });
    }
    let transaction = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(input.funding.txid, input.funding.vout),
            sequence: bitcoin::Sequence(0xffff_fffd),
            ..TxIn::default()
        }],
        output: outputs,
    };
    let txid = transaction.compute_txid();
    let mut psbt = Psbt::from_unsigned_tx(transaction)?;
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: funding_amount,
        script_pubkey: address.script_pubkey(),
    });
    psbt.inputs[0].tap_internal_key = Some(key);
    psbt.inputs[0].tap_merkle_root = Some(contract::recovery_root(&instance)?);
    psbt.inputs[0].sighash_type = Some(TapSighashType::All.into());
    let summary = json!({
        "funding": input.funding, "recipient": recipient.to_string(), "amount_sats": input.amount_sats,
        "fee_sats": input.fee_sats, "change_sats": change, "change_address": address.to_string(),
        "txid": txid.to_string(), "network": app.network,
    });
    Ok((instance, psbt, summary, recovery))
}

/// Check the exact PSBT shape for the selected path. Callers separately enforce
/// the guest-backed passkey authorization or the two-key recovery signature.
fn check_signing_psbt(
    app: &Wallet<'_>,
    instance: &ProgramInstance,
    psbt: &Psbt,
    recovery: Option<&contract::Recovery>,
) -> Result<u64> {
    ensure!(
        psbt.inputs.len() == 1 && psbt.unsigned_tx.input.len() == 1,
        "example signs exactly one funding input"
    );
    ensure!(
        psbt.unsigned_tx.version == bitcoin::transaction::Version::TWO
            && psbt.unsigned_tx.lock_time == bitcoin::absolute::LockTime::ZERO
            && psbt.unsigned_tx.input[0].sequence == bitcoin::Sequence(0xffff_fffd)
            && psbt.unsigned_tx.input[0].previous_output.txid != Txid::all_zeros(),
        "unexpected transaction version, locktime, sequence or funding outpoint"
    );
    ensure!(
        (1..=2).contains(&psbt.unsigned_tx.output.len()),
        "expected payment and optional change output"
    );
    let key = contract::derive_public_key(instance, app.root)?;
    let root = contract::recovery_root(instance)?;
    let funding_script = contract::funding_script(key, root);
    let prevout = psbt.inputs[0]
        .witness_utxo
        .as_ref()
        .context("missing funding prevout")?;
    checked_sats(prevout.value.to_sat(), "funding value")?;
    ensure!(
        prevout.script_pubkey == funding_script,
        "funding script does not match the committed passkey wallet"
    );
    let mut expected = Psbt::from_unsigned_tx(psbt.unsigned_tx.clone())?;
    expected.inputs[0].witness_utxo = Some(prevout.clone());
    expected.inputs[0].tap_internal_key = Some(key);
    expected.inputs[0].tap_merkle_root = Some(root);
    expected.inputs[0].sighash_type = Some(TapSighashType::All.into());
    if let Some(recovery) = recovery {
        attach_recovery(&mut expected, recovery)?;
    }
    ensure!(
        *psbt == expected,
        "unexpected PSBT metadata, signature, annex, or alternate Taproot path"
    );
    let mut total = 0u64;
    for (index, output) in psbt.unsigned_tx.output.iter().enumerate() {
        checked_sats(output.value.to_sat(), "output value")?;
        ensure!(
            output.value >= output.script_pubkey.minimal_non_dust(),
            "output is dust"
        );
        ensure!(
            output.script_pubkey.is_p2wpkh()
                || output.script_pubkey.is_p2wsh()
                || output.script_pubkey.is_p2tr(),
            "unsupported recipient script"
        );
        if index == 1 {
            ensure!(
                output.script_pubkey == funding_script,
                "change must return to the passkey wallet"
            );
        }
        total = total
            .checked_add(output.value.to_sat())
            .context("output sum overflow")?;
    }
    let fee = prevout
        .value
        .to_sat()
        .checked_sub(total)
        .context("outputs exceed funding")?;
    checked_sats(fee, "fee")?;
    Ok(fee)
}

fn finalize(mut signed: Psbt, original_txid: Txid, fee: u64) -> Result<Value> {
    signed
        .finalize_mut(&Secp256k1::verification_only())
        .map_err(|errors| anyhow!("could not finalize verified Taproot signature: {errors:?}"))?;
    let signed_psbt = STANDARD.encode(signed.serialize());
    let transaction = signed
        .extract_tx()
        .context("extracting transaction with fee-rate safety check")?;
    ensure!(
        transaction.compute_txid() == original_txid,
        "finalization changed the unsigned transaction"
    );
    Ok(
        json!({"txid": transaction.compute_txid().to_string(), "transaction_hex": hex::encode(serialize(&transaction)), "signed_psbt": signed_psbt, "fee_sats": fee}),
    )
}

fn parse_body<T: serde::de::DeserializeOwned>(body: Value) -> Result<T> {
    // Do not reflect caller-supplied field values in ABI errors.
    serde_json::from_value(body).map_err(|_| anyhow!("invalid operation body"))
}

fn decode_psbt(encoded: &str) -> Result<Psbt> {
    ensure!(
        encoded.len() <= MAX_PSBT.div_ceil(3) * 4,
        "PSBT exceeds 64 KiB"
    );
    let bytes = STANDARD.decode(encoded).context("invalid base64 PSBT")?;
    ensure!(bytes.len() <= MAX_PSBT, "PSBT exceeds 64 KiB");
    Psbt::deserialize(&bytes).context("invalid PSBT")
}

fn nonce(encoded: &str) -> Result<[u8; 32]> {
    ensure!(
        encoded.len() == 64
            && encoded
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "nonce must be 32-byte lowercase hex"
    );
    decode_hex(encoded, 32, "nonce")?
        .try_into()
        .map_err(|_| anyhow!("nonce must be 32 bytes"))
}

pub(crate) fn dispatch(app: &Wallet<'_>, operation: &str, body: Value) -> Result<Value> {
    match operation {
        "configure" => {
            ensure!(
                body.as_object().is_some_and(|body| body.is_empty()),
                "configure requires an empty object"
            );
            let recipient = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([42; 20]));
            Ok(json!({
                "rp_id": app.rp_id, "origin": app.origin, "network": app.network,
                "genesis_hash": hex::encode(bitcoin::blockdata::constants::genesis_block(app.network).block_hash().to_byte_array()),
                "xpub": app.root.to_string(), "module_sha256": hex::encode(contract::hash(contract::WASM)),
                "module_bytes": contract::WASM.len(), "local_dev": app.local_dev,
                "default_recipient": Address::from_script(&recipient, app.network)?.to_string(),
            }))
        }
        "wallet" => {
            let input: WalletInput = parse_body(body)?;
            let (instance, recovery) = policy(app, &input.public_key, &input.recovery_keys)?;
            let key = contract::derive_public_key(&instance, app.root)?;
            let script = contract::funding_script(key, contract::recovery_root(&instance)?);
            let address = Address::from_script(&script, app.network)?;
            Ok(json!({
                "parameters": hex::encode(instance.parameters()), "program_id": instance.id(),
                "address": address.to_string(), "script_pubkey": hex::encode(script.as_bytes()),
                "internal_key": key.to_string(), "recovery": recovery_descriptor(key, &recovery)?,
                "synthetic_funding": synthetic_funding(script),
            }))
        }
        "prepare" => prepare(app, parse_body(body)?),
        "request" => request(app, parse_body(body)?),
        "finalize_passkey" => finalize_passkey(app, parse_body(body)?),
        "finalize_recovery" => finalize_recovery(app, parse_body(body)?),
        _ => anyhow::bail!("unknown wallet operation"),
    }
}

fn prepare(app: &Wallet<'_>, input: PrepareInput) -> Result<Value> {
    let (instance, mut psbt, summary, recovery) = prepare_transaction(app, &input)?;
    let key = psbt.inputs[0]
        .tap_internal_key
        .context("missing wallet internal key")?;
    let mut descriptor = recovery_descriptor(key, &recovery)?;
    let view = contract::signed_view(&psbt, 0)?;
    let mut result = json!({
        "parameters": hex::encode(instance.parameters()),
        "address": summary["change_address"],
        "program_id": instance.id(), "summary": summary,
    });
    match input.path {
        SpendPath::Passkey => {
            let nonce = nonce(
                input
                    .nonce
                    .as_deref()
                    .context("passkey preparation requires a fresh browser nonce")?,
            )?;
            result["nonce"] = hex::encode(nonce).into();
            result["challenge"] =
                hex::encode(contract::challenge(instance.parameters(), &view, &nonce)).into();
        }
        SpendPath::Recovery => {
            ensure!(
                input.nonce.is_none(),
                "recovery preparation does not accept a passkey nonce"
            );
            attach_recovery(&mut psbt, &recovery)?;
            descriptor["sighash"] = hex::encode(recovery_sighash(&psbt, &recovery)?).into();
        }
    }
    result["view"] = hex::encode(view).into();
    result["psbt"] = STANDARD.encode(psbt.serialize()).into();
    result["recovery"] = descriptor;
    Ok(result)
}

fn request(app: &Wallet<'_>, input: SignInput) -> Result<Value> {
    let (instance, _) = policy(app, &input.public_key, &input.recovery_keys)?;
    let psbt = decode_psbt(&input.psbt)?;
    check_signing_psbt(app, &instance, &psbt, None)?;
    let nonce = nonce(&input.nonce)?;
    let auth = decode_hex(&input.authenticator_data, 37, "authenticator data")?;
    let client_data = decode_hex(
        &input.client_data_json,
        contract::MAX_CLIENT_DATA,
        "clientDataJSON",
    )?;
    let signature = decode_hex(&input.signature, 72, "signature")?;
    Ok(serde_json::to_value(OracleRequest::SignProgramV1(
        SigningRequest {
            instance,
            input_index: 0,
            witness: contract::witness(&nonce, &auth, &client_data, &signature)?,
            path: ProgramSpendPath::KeyPath,
            psbt: WirePsbt(psbt),
        },
    ))?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyFinalization {
    request: OracleRequest,
    response: OracleResponse,
}

/// Authenticate the original request's policy to the loaded static context.
fn check_instance(app: &Wallet<'_>, instance: &ProgramInstance) -> Result<()> {
    ensure!(
        instance.evaluator() == EvaluatorId::wasm_v2() && instance.program() == contract::WASM,
        "request does not use the pinned inline passkey evaluator"
    );
    contract::recovery_root(instance)?;
    let parameters = instance.parameters();
    ensure!(
        parameters[4..36]
            == bitcoin::blockdata::constants::genesis_block(app.network)
                .block_hash()
                .to_byte_array(),
        "request policy uses a different Bitcoin network"
    );
    ensure!(
        matches!(parameters[36], 2 | 3),
        "invalid compressed passkey public key"
    );
    p256::PublicKey::from_sec1_bytes(&parameters[36..69])
        .map_err(|_| anyhow!("invalid policy passkey"))?;
    ensure!(
        parameters[101..133] == contract::hash(app.rp_id.as_bytes())
            && &parameters[137..] == app.origin.as_bytes(),
        "request policy has a different WebAuthn context"
    );
    Ok(())
}

fn check_witness(witness: &[u8]) -> Result<()> {
    ensure!(witness.len() >= 32, "truncated passkey witness");
    let nonce: &[u8; 32] = witness[..32].try_into()?;
    let mut remaining = &witness[32..];
    let mut fields = [&[][..]; 3];
    for field in &mut fields {
        ensure!(remaining.len() >= 4, "truncated passkey witness field");
        let length = u32::from_le_bytes(remaining[..4].try_into()?) as usize;
        remaining = &remaining[4..];
        ensure!(
            length <= remaining.len(),
            "truncated passkey witness payload"
        );
        *field = &remaining[..length];
        remaining = &remaining[length..];
    }
    ensure!(remaining.is_empty(), "trailing passkey witness bytes");
    // Reuse the policy's exact field bounds and canonical framing.
    ensure!(
        contract::witness(nonce, fields[0], fields[1], fields[2])? == witness,
        "invalid passkey witness"
    );
    Ok(())
}

fn finalize_passkey(app: &Wallet<'_>, input: PasskeyFinalization) -> Result<Value> {
    let OracleRequest::SignProgramV1(request) = input.request;
    ensure!(
        request.input_index == 0 && request.path == ProgramSpendPath::KeyPath,
        "only the selected passkey key-path signature is supported"
    );
    check_instance(app, &request.instance)?;
    check_witness(&request.witness)?;
    let mut original = request.psbt.0;
    let fee = check_signing_psbt(app, &request.instance, &original, None)?;
    let signed = match input.response {
        OracleResponse::SignedV1(WirePsbt(psbt)) => psbt,
        OracleResponse::RejectedV1(reason) => {
            anyhow::bail!("oracle rejected passkey authorization: {reason}")
        }
    };
    let signature = signed
        .inputs
        .first()
        .and_then(|input| input.tap_key_sig)
        .context("oracle response is missing the requested signature")?;
    ensure!(
        signature.sighash_type == TapSighashType::All,
        "oracle response must use explicit SIGHASH_ALL"
    );
    let prevout = original.inputs[0]
        .witness_utxo
        .as_ref()
        .context("missing funding prevout")?;
    let sighash = SighashCache::new(&original.unsigned_tx).taproot_key_spend_signature_hash(
        0,
        &Prevouts::All(&[prevout]),
        TapSighashType::All,
    )?;
    let secp = Secp256k1::verification_only();
    // These fields were independently matched to the pinned program derivation
    // and recovery commitment by check_signing_psbt, never taken from response.
    let key = original.inputs[0]
        .tap_internal_key
        .context("missing verified wallet internal key")?;
    let output_key = key.tap_tweak(&secp, original.inputs[0].tap_merkle_root).0;
    secp.verify_schnorr(
        &signature.signature,
        &Message::from_digest(sighash.to_byte_array()),
        &output_key.to_x_only_public_key(),
    )
    .context("invalid oracle signature for the pinned wallet and original PSBT")?;
    original.inputs[0].tap_key_sig = Some(signature);
    ensure!(
        signed == original,
        "oracle response modified unrelated PSBT data"
    );
    let txid = original.unsigned_tx.compute_txid();
    finalize(signed, txid, fee)
}

fn finalize_recovery(app: &Wallet<'_>, input: RecoveryInput) -> Result<Value> {
    let (instance, recovery) = policy(app, &input.public_key, &input.recovery_keys)?;
    let mut psbt = decode_psbt(&input.psbt)?;
    let fee = check_signing_psbt(app, &instance, &psbt, Some(&recovery))?;
    let signature = schnorr::Signature::from_slice(&decode_hex(&input.signature, 64, "signature")?)
        .context("recovery requires one aggregated 64-byte Schnorr signature")?;
    Secp256k1::verification_only()
        .verify_schnorr(
            &signature,
            &Message::from_digest(recovery_sighash(&psbt, &recovery)?),
            &recovery.aggregate_key,
        )
        .context("invalid two-key recovery signature")?;
    psbt.inputs[0].tap_script_sigs.insert(
        (recovery.aggregate_key, recovery.leaf_hash),
        bitcoin::taproot::Signature {
            signature,
            sighash_type: TapSighashType::All,
        },
    );
    let txid = psbt.unsigned_tx.compute_txid();
    finalize(psbt, txid, fee)
}
