//! Exercise a remote ProgramOracle with disposable, never-broadcast funding.
//!
//! The identity file must come from an independent attestation verifier. This
//! example checks its protocol/profile, but does NOT verify Nitro COSE evidence.
//! It never fetches an identity from the endpoint or derives an oracle secret.

use anyhow::{bail, ensure, Context, Result};
use bitcoin::bip32::Xpub;
use bitcoin::blockdata::opcodes::all::OP_CHECKSIG;
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};
use emulator_connect::program::{
    ProgramClient, ProgramClientError, ProgramSigningRequest, ProgramSpendPath, PSBT,
};
use sapio_base::program::{ctv_wasm_instance, EvaluatorId, ProgramInstance};
use sapio_base::{CTVHash, Ctv};
use sapio_tee::deployment::{
    program_profile, ProgramProfile, IDENTITY_PROTOCOL, PAY_AT_LEAST_SELECTOR, PAY_AT_LEAST_WASM,
};
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;

const MAX_IDENTITY_BYTES: u64 = 64 * 1024;
const MINIMUM: u64 = 9_000;
const FUNDING: u64 = 20_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    protocol: String,
    mode: String,
    xpub: Xpub,
    settings: serde_json::Value,
    signing: ProgramProfile,
}

struct Options {
    address: SocketAddr,
    identity: PathBuf,
    allow_local_dev: bool,
}

fn options() -> Result<Option<Options>> {
    let mut args = std::env::args_os().skip(1);
    let mut address = None;
    let mut identity = None;
    let mut allow_local_dev = false;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--help") => {
                println!(
                    "Usage: program_oracle --address IP:PORT --identity FILE [--allow-local-dev]\n\
                     FILE must be the exact identity JSON accepted by an independent Nitro\n\
                     attestation verifier, using independently trusted measurements and settings.\n\
                     This example does NOT verify COSE or trust/fetch /public-key.\n\
                     --allow-local-dev permits an unattested local-dev identity with null settings\n\
                     and a test-network xpub, solely for synthetic regtest fixtures.\n\
                     All funding is synthetic. Nothing is broadcast; no private keys are needed."
                );
                return Ok(None);
            }
            Some("--address") if address.is_none() => {
                let value = args.next().context("--address needs IP:PORT")?;
                address = Some(
                    value
                        .to_str()
                        .context("address must be UTF-8")?
                        .parse()
                        .context("address must be an explicit numeric SocketAddr")?,
                );
            }
            Some("--identity") if identity.is_none() => {
                identity = Some(PathBuf::from(args.next().context("--identity needs FILE")?));
            }
            Some("--allow-local-dev") if !allow_local_dev => allow_local_dev = true,
            _ => bail!("unknown or repeated argument: {argument:?}; use --help"),
        }
    }
    Ok(Some(Options {
        address: address.context("--address is required; use --help")?,
        identity: identity.context("--identity is required; use --help")?,
        allow_local_dev,
    }))
}

fn load_identity(options: &Options) -> Result<Identity> {
    let mut bytes = Vec::new();
    File::open(&options.identity)
        .context("opening identity file")?
        .take(MAX_IDENTITY_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_IDENTITY_BYTES,
        "identity exceeds 64 KiB"
    );
    let identity: Identity = serde_json::from_slice(&bytes).context("parsing identity JSON")?;
    ensure!(
        identity.protocol == IDENTITY_PROTOCOL,
        "unsupported identity protocol"
    );
    ensure!(
        identity.signing == program_profile(),
        "identity has an unexpected program profile"
    );
    match identity.mode.as_str() {
        "nitro" => {
            ensure!(
                identity.settings.is_object(),
                "Nitro identity requires settings"
            );
        }
        "local-dev" if options.allow_local_dev => {
            ensure!(
                identity.settings.is_null(),
                "local-dev settings must be null"
            );
            ensure!(
                identity.xpub.network == Network::Regtest.into(),
                "local-dev requires a test-network xpub"
            );
            eprintln!(
                "WARNING: unattested local-dev identity; synthetic regtest demonstration only"
            );
        }
        _ => bail!("expected nitro identity (local-dev requires --allow-local-dev)"),
    }
    Ok(identity)
}

// Native P2WPKH scripts identify disposable recipients without holding keys.
fn recipient(tag: u8) -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([tag; 20]))
}

fn payment_instance() -> Result<ProgramInstance> {
    let script = recipient(1);
    let mut parameters = MINIMUM.to_le_bytes().to_vec();
    parameters.extend_from_slice(&(script.len() as u32).to_le_bytes());
    parameters.extend_from_slice(script.as_bytes());
    Ok(ProgramInstance::new(
        EvaluatorId::for_wasm(PAY_AT_LEAST_WASM),
        PAY_AT_LEAST_SELECTOR.to_vec(),
        parameters,
    )?)
}

fn transaction() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::from_consensus(500),
        input: vec![
            TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([1; 32]), 0),
                sequence: bitcoin::Sequence(100),
                ..TxIn::default()
            },
            TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([2; 32]), 0),
                sequence: bitcoin::Sequence(200),
                ..TxIn::default()
            },
        ],
        output: vec![
            TxOut {
                value: Amount::from_sat(MINIMUM),
                script_pubkey: recipient(1),
            },
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: recipient(2),
            },
        ],
    }
}

/// Bind the selected input (deliberately index ONE) to synthetic funding.
/// All other prevouts are native witness outputs, as required by the CTV guest.
fn request(
    root: &Xpub,
    instance: ProgramInstance,
    mut transaction: Transaction,
    script_path: bool,
) -> Result<ProgramSigningRequest> {
    let secp = Secp256k1::verification_only();
    let key = instance.derive_public_key(root)?;
    let leaf = script_path.then(|| {
        Builder::new()
            .push_slice(key.serialize())
            .push_opcode(OP_CHECKSIG)
            .into_script()
    });
    let mut builder = TaprootBuilder::new();
    if let Some(script) = &leaf {
        builder = builder.add_leaf(0, script.clone())?;
    }
    let spend = builder
        .finalize(&secp, key)
        .map_err(|_| anyhow::anyhow!("incomplete Taproot tree"))?;
    let funding_output = TxOut {
        value: Amount::from_sat(FUNDING),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(spend.output_key()),
    };
    let funding = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![funding_output.clone()],
    };
    transaction.input[1].previous_output = OutPoint::new(funding.compute_txid(), 0);
    let mut psbt = Psbt::from_unsigned_tx(transaction)?;
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: recipient(3),
    });
    psbt.inputs[1].witness_utxo = Some(funding_output);
    psbt.inputs[1].tap_internal_key = Some(key);
    psbt.inputs[1].tap_merkle_root = spend.merkle_root();
    let path = if let Some(script) = leaf {
        let leaf = (script, LeafVersion::TapScript);
        let hash = TapLeafHash::from_script(&leaf.0, leaf.1);
        let control = spend
            .control_block(&leaf)
            .context("missing generated control block")?;
        psbt.inputs[1].tap_scripts.insert(control, leaf);
        ProgramSpendPath::ScriptPath(hash)
    } else {
        ProgramSpendPath::KeyPath
    };
    Ok(ProgramSigningRequest {
        instance,
        input_index: 1,
        witness: vec![],
        path,
        psbt: PSBT(psbt),
    })
}

/// Predicate comparisons must spend the SAME funding under the SAME commitment.
fn same_commitment_and_funding(a: &ProgramSigningRequest, b: &ProgramSigningRequest) -> Result<()> {
    ensure!(
        a.instance == b.instance && a.path == b.path,
        "fixture changed program commitment/path"
    );
    ensure!(
        a.input_index == b.input_index,
        "fixture changed selected input"
    );
    ensure!(
        a.psbt.0.unsigned_tx.input == b.psbt.0.unsigned_tx.input,
        "fixture changed funding inputs"
    );
    for (a, b) in a.psbt.0.inputs.iter().zip(&b.psbt.0.inputs) {
        ensure!(
            a.witness_utxo == b.witness_utxo,
            "fixture changed funding output"
        );
    }
    Ok(())
}

async fn accepted(
    client: &ProgramClient,
    request: &ProgramSigningRequest,
    label: &str,
) -> Result<()> {
    // ProgramClient cryptographically verifies SIGHASH_ALL for the derived key,
    // selected input and path, and rejects ANY unrelated PSBT modification.
    client
        .sign(request.clone())
        .await
        .with_context(|| format!("{label}: expected valid signature"))?;
    println!("PASS {label} (signature and unchanged PSBT fields verified)");
    Ok(())
}

async fn rejected(
    client: &ProgramClient,
    request: ProgramSigningRequest,
    label: &str,
) -> Result<()> {
    match client.sign(request).await {
        Err(ProgramClientError::Rejected(_)) => {
            println!("PASS {label} (remote typed rejection)");
            Ok(())
        }
        Err(error) => {
            bail!("{label}: expected Rejected, not transport/validation failure: {error}")
        }
        Ok(_) => bail!("{label}: unexpectedly received a signature"),
    }
}

async fn payments(client: &ProgramClient, root: &Xpub) -> Result<ProgramSigningRequest> {
    let instance = payment_instance()?;
    let mut original = request(root, instance.clone(), transaction(), false)?;
    original.witness = 0_u32.to_le_bytes().to_vec();
    accepted(
        client,
        &original,
        "registered payment: minimum to output 0, key path/input 1",
    )
    .await?;

    let mut alternative = original.clone();
    alternative.psbt.0.unsigned_tx.output[0].value = Amount::from_sat(11_000);
    alternative.psbt.0.unsigned_tx.output[1].value = Amount::from_sat(8_000);
    alternative.psbt.0.unsigned_tx.output.swap(0, 1);
    alternative.witness = 1_u32.to_le_bytes().to_vec();
    same_commitment_and_funding(&original, &alternative)?;
    accepted(
        client,
        &alternative,
        "same payment commitment/funding: larger payment to output 1",
    )
    .await?;

    let mut underpaid = original.clone();
    underpaid.psbt.0.unsigned_tx.output[0].value = Amount::from_sat(MINIMUM - 1);
    same_commitment_and_funding(&original, &underpaid)?;
    rejected(client, underpaid, "underpayment").await?;
    let mut redirected = original.clone();
    redirected.psbt.0.unsigned_tx.output[0].script_pubkey = recipient(4);
    same_commitment_and_funding(&original, &redirected)?;
    rejected(client, redirected, "redirected recipient").await?;
    let mut malformed = original.clone();
    malformed.witness.pop();
    same_commitment_and_funding(&original, &malformed)?;
    rejected(client, malformed, "malformed output-index evidence").await?;

    let mut script = request(root, instance, transaction(), true)?;
    script.witness = 0_u32.to_le_bytes().to_vec();
    accepted(client, &script, "authenticated payment script path/input 1").await?;
    let mut unauthenticated = script;
    unauthenticated.psbt.0.inputs[1].tap_scripts.clear();
    rejected(
        client,
        unauthenticated,
        "missing script-path authentication",
    )
    .await?;

    let mut substituted = original.clone();
    let mut parameters = substituted.instance.parameters().to_vec();
    parameters[..8].copy_from_slice(&1_u64.to_le_bytes());
    substituted.instance = ProgramInstance::new(
        substituted.instance.evaluator(),
        PAY_AT_LEAST_SELECTOR.to_vec(),
        parameters,
    )?;
    rejected(
        client,
        substituted,
        "different instance cannot authorize original funding",
    )
    .await?;

    // A correctly bound key with an unregistered evaluator tests dispatch, not
    // merely a key/funding mismatch. This ID is outside the accepted profile.
    let unknown = ProgramInstance::new(
        EvaluatorId::for_wasm(b"unregistered demonstration interpreter"),
        vec![],
        vec![],
    )?;
    rejected(
        client,
        request(root, unknown, transaction(), false)?,
        "unknown evaluator",
    )
    .await?;
    Ok(original)
}

async fn ctv(client: &ProgramClient, root: &Xpub) -> Result<()> {
    let tx = transaction();
    let instance = ctv_wasm_instance(Ctv(tx.get_ctv_hash(1)));
    // CTV excludes outpoints, so binding synthetic funding preserves this hash.
    let original = request(root, instance, tx, false)?;
    accepted(
        client,
        &original,
        "inline v1 CTV with native-witness prevouts/input 1",
    )
    .await?;
    let mut changed = original.clone();
    changed.psbt.0.unsigned_tx.output[0].value += Amount::ONE_SAT;
    same_commitment_and_funding(&original, &changed)?;
    rejected(
        client,
        changed,
        "changed CTV template under original commitment/funding",
    )
    .await
}

/// V2 ABI: the signed view retains v1's lock-time u32 at offset 4.
/// Parameters fix the ONLY permitted lock time; evidence cannot override it.
fn v2_module(body: &str) -> Result<Vec<u8>> {
    Ok(wat::parse_str(format!(
        r#"(module
            (memory (export "memory") 1)
            (global $heap (mut i32) (i32.const 1024))
            (func (export "sapio_alloc_v2") (param $len i32) (result i32)
                (local $ptr i32)
                global.get $heap local.tee $ptr
                local.get $len i32.add global.set $heap local.get $ptr)
            (func (export "sapio_evaluate_v2")
                (param $program i32) (param $program_len i32)
                (param $params i32) (param $params_len i32)
                (param $view i32) (param $view_len i32)
                (param $witness i32) (param $witness_len i32) (result i32)
                {body}))"#
    ))?)
}

async fn inline_v2(client: &ProgramClient, root: &Xpub) -> Result<()> {
    let module = v2_module(
        "local.get $program_len i32.eqz
         local.get $params_len i32.const 4 i32.eq i32.and
         local.get $witness_len i32.eqz i32.and
         local.get $view_len i32.const 52 i32.ge_u i32.and
         if (result i32)
             local.get $view i32.load offset=4
             local.get $params i32.load i32.eq
         else i32.const 0 end",
    )?;
    let instance = ProgramInstance::wasm_v2(module, 500_u32.to_le_bytes().to_vec())?;
    let original = request(root, instance, transaction(), false)?;
    accepted(
        client,
        &original,
        "inline v2 signed lock-time predicate/input 1",
    )
    .await?;
    let mut changed = original.clone();
    changed.psbt.0.unsigned_tx.lock_time = bitcoin::absolute::LockTime::from_consensus(501);
    same_commitment_and_funding(&original, &changed)?;
    rejected(client, changed, "v2 rejects changed signed lock time").await?;

    let trap = ProgramInstance::wasm_v2(v2_module("unreachable")?, vec![])?;
    rejected(
        client,
        request(root, trap, transaction(), false)?,
        "v2 trap fails closed",
    )
    .await?;

    let exhausted = ProgramInstance::wasm_v2(v2_module("(loop br 0) i32.const 1")?, vec![])?;
    rejected(
        client,
        request(root, exhausted, transaction(), false)?,
        "v2 infinite loop exhausts fuel and fails closed",
    )
    .await
}

#[tokio::main]
async fn main() -> Result<()> {
    let Some(options) = options()? else {
        return Ok(());
    };
    let identity = load_identity(&options)?;
    let client = ProgramClient::new(options.address, identity.xpub)?;
    let payment = payments(&client, &identity.xpub).await?;
    ctv(&client, &identity.xpub).await?;
    inline_v2(&client, &identity.xpub).await?;
    accepted(
        &client,
        &payment,
        "server remains live after rejected predicates, trap and fuel exhaustion",
    )
    .await?;
    println!("PASS remote ProgramOracle demonstration; synthetic funding only, nothing broadcast");
    Ok(())
}
