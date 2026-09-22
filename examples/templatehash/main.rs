//! Emulate BIP-446 OP_TEMPLATEHASH with an inline v1 predicate.
//!
//! The committed program is templatehash.wasm plus a 32-byte template hash.
//! The oracle signs only the transaction that reproduces that hash. Hashes are
//! computed client-side per the BIP and cross-checked against rust-bitcoin's
//! own BIP341 sighash assembly. One fixture is a BIP-446 test-vector
//! transaction produced by Bitcoin Core. Synthetic funding; nothing broadcast.
//! The identity must come from an independent attestation verifier.

#[path = "../support/mod.rs"]
mod support;

use anyhow::{bail, ensure, Context, Result};
use bitcoin::bip32::Xpub;
use bitcoin::consensus::Decodable;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighash, TapSighashType};
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};
use emulator_connect::program::{
    ProgramClient, ProgramClientError, ProgramSigningRequest, ProgramSpendPath, PSBT,
};
use sapio_base::program::ProgramInstance;
use sha2::{Digest, Sha256};

const TEMPLATEHASH_WASM: &[u8] = include_bytes!("templatehash.wasm");
const DIGEST: usize = 32;

/// The first "valid" case of the BIP-446 basics.json test vectors: a
/// two-input transaction and its spent outputs, produced by Bitcoin Core.
const VECTOR_TX: &str = "02000000000102c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37041500000000ffffffff169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f40c00000000ffffffff01327906000000000016001482074bdf6ce32b071dd120a17cf99cbc01ad3080022320d1f1955b1327167cb7ae3dc39d52c277be39d75737b9cb80514ce6e825fd8eeace8721c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00000000000";
const VECTOR_SPENT: [&str; 2] = [
    "33790600000000002251205331c80448b5eb2daad3567c98bc99664d14e0ea12bdf3be755429055d67756a",
    "22921000000000001976a914079ded3e3befdab0757fe0e8842aeffc0ff2160288ac",
];

fn sha256(data: &[u8]) -> [u8; DIGEST] {
    Sha256::digest(data).into()
}

fn tagged_hash(tag: &str, message: &[u8]) -> [u8; DIGEST] {
    let tag_hash = sha256(tag.as_bytes());
    let mut buffer = Vec::with_capacity(2 * DIGEST + message.len());
    buffer.extend_from_slice(&tag_hash);
    buffer.extend_from_slice(&tag_hash);
    buffer.extend_from_slice(message);
    sha256(&buffer)
}

fn push_compact_size(buffer: &mut Vec<u8>, length: u64) {
    if length < 253 {
        buffer.push(length as u8);
    } else if length <= 0xFFFF {
        buffer.push(0xFD);
        buffer.extend_from_slice(&(length as u16).to_le_bytes());
    } else if length <= 0xFFFF_FFFF {
        buffer.push(0xFE);
        buffer.extend_from_slice(&(length as u32).to_le_bytes());
    } else {
        buffer.push(0xFF);
        buffer.extend_from_slice(&length.to_le_bytes());
    }
}

fn sha_sequences(transaction: &Transaction) -> [u8; DIGEST] {
    let mut buffer = Vec::with_capacity(4 * transaction.input.len());
    for input in &transaction.input {
        buffer.extend_from_slice(&input.sequence.0.to_le_bytes());
    }
    sha256(&buffer)
}

fn sha_outputs(transaction: &Transaction) -> [u8; DIGEST] {
    let mut buffer = Vec::new();
    for output in &transaction.output {
        buffer.extend_from_slice(&output.value.to_sat().to_le_bytes());
        push_compact_size(&mut buffer, output.script_pubkey.len() as u64);
        buffer.extend_from_slice(output.script_pubkey.as_bytes());
    }
    sha256(&buffer)
}

/// BIP-446 template hash, no-annex case, exactly as the predicate recomputes.
fn template_hash(transaction: &Transaction, input_index: u32) -> [u8; DIGEST] {
    let mut message = Vec::with_capacity(77);
    message.extend_from_slice(&transaction.version.0.to_le_bytes());
    message.extend_from_slice(&transaction.lock_time.to_consensus_u32().to_le_bytes());
    message.extend_from_slice(&sha_sequences(transaction));
    message.extend_from_slice(&sha_outputs(transaction));
    message.push(0); // annex_present: no annex
    message.extend_from_slice(&input_index.to_le_bytes());
    tagged_hash("TemplateHash", &message)
}

/// The BIP-446 sub-hashes must be byte-identical to rust-bitcoin's own BIP341
/// sighash components: assemble the full sighash from ours and compare.
fn crosscheck_sighash(
    transaction: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
) -> Result<()> {
    let mut cache = SighashCache::new(transaction);
    let theirs = cache
        .taproot_signature_hash(
            input_index,
            &Prevouts::All(prevouts),
            None,
            None,
            TapSighashType::All,
        )
        .context("rust-bitcoin sighash failed")?;

    let mut sha_prevouts = Vec::new();
    let mut sha_amounts = Vec::new();
    let mut sha_scriptpubkeys = Vec::new();
    for (input, prevout) in transaction.input.iter().zip(prevouts) {
        sha_prevouts.extend_from_slice(input.previous_output.txid.as_byte_array());
        sha_prevouts.extend_from_slice(&input.previous_output.vout.to_le_bytes());
        sha_amounts.extend_from_slice(&prevout.value.to_sat().to_le_bytes());
        push_compact_size(&mut sha_scriptpubkeys, prevout.script_pubkey.len() as u64);
        sha_scriptpubkeys.extend_from_slice(prevout.script_pubkey.as_bytes());
    }
    // epoch 0x00; TapSighashType::All is the explicit 0x01, not the 0x00 default.
    let mut message = vec![0x00, 0x01];
    message.extend_from_slice(&transaction.version.0.to_le_bytes());
    message.extend_from_slice(&transaction.lock_time.to_consensus_u32().to_le_bytes());
    message.extend_from_slice(&sha256(&sha_prevouts));
    message.extend_from_slice(&sha256(&sha_amounts));
    message.extend_from_slice(&sha256(&sha_scriptpubkeys));
    message.extend_from_slice(&sha_sequences(transaction));
    message.extend_from_slice(&sha_outputs(transaction));
    message.push(0x00); // spend_type: no annex, no extension
    message.extend_from_slice(&(input_index as u32).to_le_bytes());
    let mine = TapSighash::from_byte_array(tagged_hash("TapSighash", &message));
    ensure!(
        mine == theirs,
        "sha_outputs/sha_sequences diverge from rust-bitcoin's sighash"
    );
    println!("PASS sha_outputs/sha_sequences match rust-bitcoin's BIP341 sighash");
    Ok(())
}

/// Key-path funding of the selected input. Every other prevout is supplied
/// with its own witness output, mirroring the funding of a real template.
fn request(
    root: &Xpub,
    instance: ProgramInstance,
    tx: Transaction,
    input_index: usize,
) -> Result<ProgramSigningRequest> {
    let key = instance.derive_public_key(root)?;
    let mut psbt = Psbt::from_unsigned_tx(tx)?;
    for (index, input) in psbt.inputs.iter_mut().enumerate() {
        if index == input_index {
            let funding_output = TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::new_p2tr(
                    &bitcoin::secp256k1::Secp256k1::verification_only(),
                    key,
                    None,
                ),
            };
            input.witness_utxo = Some(funding_output);
            input.tap_internal_key = Some(key);
        } else if input.witness_utxo.is_none() {
            input.witness_utxo = Some(TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
                    [index as u8 + 1; 20],
                )),
            });
        }
    }
    Ok(ProgramSigningRequest {
        instance,
        input_index: input_index as u32,
        witness: vec![],
        path: ProgramSpendPath::KeyPath,
        psbt: PSBT(psbt),
    })
}

fn instance_for(transaction: &Transaction, input_index: u32) -> Result<ProgramInstance> {
    Ok(ProgramInstance::wasm(
        TEMPLATEHASH_WASM.to_vec(),
        template_hash(transaction, input_index).to_vec(),
    )?)
}

async fn accepted(
    client: &ProgramClient,
    request: &ProgramSigningRequest,
    label: &str,
) -> Result<()> {
    client
        .sign(request.clone())
        .await
        .with_context(|| format!("{label}: expected a verified signature"))?;
    println!("PASS {label} (signature verified)");
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
        Err(error) => bail!("{label}: expected Rejected, not transport failure: {error}"),
        Ok(_) => bail!("{label}: unexpectedly received a signature"),
    }
}

fn template_transaction() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::from_consensus(800_000),
        input: vec![
            TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([7; 32]), 0),
                sequence: bitcoin::Sequence(0xffff_fffd),
                ..TxIn::default()
            },
            TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([8; 32]), 1),
                sequence: bitcoin::Sequence(0xffff_fffd),
                ..TxIn::default()
            },
        ],
        output: vec![
            TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
                    [42; 20],
                )),
            },
            TxOut {
                value: Amount::from_sat(500),
                script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
                    [43; 20],
                )),
            },
        ],
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let Some(options) = support::options("templatehash")? else {
        return Ok(());
    };
    let identity = support::load_identity(&options)?;
    let client = ProgramClient::new(options.address, identity.xpub)?;

    let tx = template_transaction();
    let instance = instance_for(&tx, 0)?;
    let original = request(&identity.xpub, instance, tx.clone(), 0)?;
    let prevouts: Vec<TxOut> = original
        .psbt
        .0
        .inputs
        .iter()
        .map(|input| input.witness_utxo.clone().expect("all prevouts supplied"))
        .collect();
    crosscheck_sighash(&tx, 0, &prevouts)?;
    accepted(&client, &original, "exact BIP-446 template match, input 0").await?;

    // A Bitcoin Core-produced transaction from the BIP-446 test vectors.
    let vector_bytes = hex::decode(VECTOR_TX)?;
    let vector_tx = Transaction::consensus_decode(&mut vector_bytes.as_slice())?;
    let vector_prevouts: Vec<TxOut> = VECTOR_SPENT
        .iter()
        .map(|raw| {
            let bytes = hex::decode(raw).expect("vector hex");
            TxOut::consensus_decode(&mut bytes.as_slice()).expect("vector TxOut")
        })
        .collect();
    ensure!(
        vector_tx.input.len() == vector_prevouts.len(),
        "vector prevout count mismatch"
    );
    crosscheck_sighash(&vector_tx, 0, &vector_prevouts)?;
    // Re-point only the selected input at our synthetic program funding and
    // drop the vector's witnesses: BIP-446 commits neither prevouts nor
    // witnesses, so the template hash is unchanged.
    let mut vector_spend = vector_tx.clone();
    vector_spend.input[0].previous_output = OutPoint::new(Txid::from_byte_array([0x42; 32]), 0);
    for input in &mut vector_spend.input {
        input.witness = bitcoin::Witness::default();
    }
    let vector_instance = instance_for(&vector_spend, 0)?;
    let vector_request = request(&identity.xpub, vector_instance, vector_spend, 0)?;
    accepted(
        &client,
        &vector_request,
        "Bitcoin Core test-vector transaction, input 0",
    )
    .await?;

    let mut wrong_hash = original.clone();
    wrong_hash.instance =
        ProgramInstance::wasm(TEMPLATEHASH_WASM.to_vec(), [0xAB; DIGEST].to_vec())?;
    rejected(&client, wrong_hash, "wrong committed template hash").await?;

    type Mutations = [(&'static str, fn(&mut Transaction)); 5];
    let mutations: Mutations = [
        ("one satoshi more in an output", |t| {
            t.output[0].value += Amount::ONE_SAT;
        }),
        ("different output script", |t| {
            t.output[1].script_pubkey =
                ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([44; 20]));
        }),
        ("changed input sequence", |t| {
            t.input[1].sequence = bitcoin::Sequence(0xffff_fffc);
        }),
        ("changed locktime", |t| {
            t.lock_time = bitcoin::absolute::LockTime::from_consensus(800_001);
        }),
        ("changed version", |t| {
            t.version = bitcoin::transaction::Version(1);
        }),
    ];
    for (label, mutate) in mutations {
        let mut mutated_tx = tx.clone();
        mutate(&mut mutated_tx);
        let mutated = request(&identity.xpub, original.instance.clone(), mutated_tx, 0)?;
        rejected(&client, mutated, label).await?;
    }

    // BIP-446 deliberately omits prevouts and amounts: the SAME template must
    // still sign when the other inputs are rebound.
    let mut rebound_tx = tx.clone();
    rebound_tx.input[1].previous_output = OutPoint::new(Txid::from_byte_array([9; 32]), 2);
    let rebound = request(&identity.xpub, original.instance.clone(), rebound_tx, 0)?;
    accepted(&client, &rebound, "rebound other input, identical template").await?;

    println!("PASS BIP-446 OP_TEMPLATEHASH emulation; synthetic funding only, nothing broadcast");
    Ok(())
}
