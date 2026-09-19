//! Compile and exercise a safe-withdrawal contract against a remote oracle.
//!
//! Anyone can trigger any policy-compliant sweep: there is no owner
//! authorization, timelock, delay or recovery path. The oracle must honestly
//! enforce the predicate. Its identity must be independently verified; this
//! client neither verifies Nitro evidence nor fetches identity from the server.
//! All funding and recipients are disposable fixtures. Nothing is broadcast.

mod contract;
#[path = "../support/mod.rs"]
mod support;

use anyhow::{anyhow, bail, ensure, Context as _, Result};
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};
use contract::SafeWithdrawal;
use emulator_connect::program::{
    prepare_program_request, ProgramClient, ProgramClientError, ProgramSigningRequest,
    ProgramSpendPath,
};
use miniscript::psbt::PsbtExt;
use sapio::contract::{Compilable, Context};
use sapio_base::effects::EffectPath;
use sapio_base::LoweringPlan;
use std::sync::Arc;

const FUNDING_SATS: u64 = 1_000_000;
const MAX_FEE_SATS: u64 = 1_000;

/// A fixed, native-witness cold-wallet stand-in; the client holds no keys.
fn recipient(tag: u8) -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([tag; 20]))
}

async fn accepted(
    client: &ProgramClient,
    request: &ProgramSigningRequest,
    label: &str,
) -> Result<()> {
    // ProgramClient verifies the derived-key SIGHASH_ALL signature and requires
    // every unrelated PSBT field to remain unchanged before returning success.
    let mut signed = client
        .sign(request.clone())
        .await
        .with_context(|| format!("{label}: expected a verified signature"))?;
    signed
        .finalize_mut(&Secp256k1::verification_only())
        .map_err(|errors| anyhow!("{label}: Miniscript finalization failed: {errors:?}"))?;
    let transaction = signed.extract_tx().context("extract finalized sweep")?;
    ensure!(
        transaction.compute_txid() == request.psbt.0.unsigned_tx.compute_txid(),
        "{label}: finalization changed the unsigned transaction"
    );
    println!(
        "PASS {label} (signature verified; Miniscript finalized and extracted txid {})",
        transaction.compute_txid()
    );
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

#[tokio::main]
async fn main() -> Result<()> {
    let Some(options) = support::options("vault")? else {
        return Ok(());
    };
    let identity = support::load_identity(&options)?;
    let client = ProgramClient::new(options.address, identity.xpub)?;
    let destination = recipient(42);
    let vault = SafeWithdrawal::new(MAX_FEE_SATS, &destination, identity.xpub)?;
    let compiled = vault
        .compile(Context::new(
            Network::Regtest,
            Amount::from_sat(FUNDING_SATS),
            LoweringPlan::Native,
            EffectPath::try_from("vault").map_err(|error| anyhow!("vault path: {error:?}"))?,
            Arc::new(Default::default()),
            None,
        ))
        .map_err(|error| anyhow!("compile safe-withdrawal contract: {error}"))?;

    // A bare program may also have a script-path alternative. Check the exact
    // committed program/root, then deliberately select ONLY its unique key path.
    let requirements = compiled.program_requirements()?;
    ensure!(
        requirements
            .iter()
            .all(|requirement| requirement.program == vault.emulation),
        "compiled artifact contains an unexpected program or oracle root"
    );
    let mut key_paths = requirements
        .iter()
        .filter(|requirement| requirement.path == ProgramSpendPath::KeyPath);
    let requirement = key_paths.next().context("vault has no program key path")?;
    ensure!(
        key_paths.next().is_none(),
        "vault has multiple program key-path requirements"
    );

    // Derive the funding script from the actual compiled Sapio output, never
    // from a hand-built approximation of its Taproot policy.
    let funding_output = TxOut {
        value: Amount::from_sat(FUNDING_SATS),
        script_pubkey: ScriptBuf::from(&compiled.address),
    };
    let funding = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![funding_output.clone()],
    };
    let transaction = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(funding.compute_txid(), 0),
            ..Default::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(FUNDING_SATS - 500),
            script_pubkey: destination.clone(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(transaction)?;
    psbt.inputs[0].witness_utxo = Some(funding_output);
    let original = prepare_program_request(&compiled, requirement, psbt, 0, vec![])?;
    println!(
        "Compiled inline-v1 vault: synthetic funding {}:0, {} sats, max fee {} sats",
        funding.compute_txid(),
        FUNDING_SATS,
        MAX_FEE_SATS
    );
    accepted(&client, &original, "500-sat fee to committed recipient").await?;

    // Every predicate case clones this same unsigned request. The instance,
    // selected input 0, funding outpoint and its witness_utxo remain unchanged.
    let mut maximum = original.clone();
    maximum.psbt.0.unsigned_tx.output[0].value = Amount::from_sat(FUNDING_SATS - MAX_FEE_SATS);
    accepted(
        &client,
        &maximum,
        "exact 1000-sat maximum fee under same instance/funding",
    )
    .await?;

    let mut excessive_fee = original.clone();
    excessive_fee.psbt.0.unsigned_tx.output[0].value = Amount::from_sat(FUNDING_SATS - 1_001);
    rejected(&client, excessive_fee, "1001-sat fee exceeds committed cap").await?;

    let mut redirected = original.clone();
    redirected.psbt.0.unsigned_tx.output[0].script_pubkey = recipient(43);
    rejected(
        &client,
        redirected,
        "different recipient at allowed 500-sat fee",
    )
    .await?;

    let mut negative_fee = original.clone();
    negative_fee.psbt.0.unsigned_tx.output[0].value = Amount::from_sat(FUNDING_SATS + 1);
    rejected(&client, negative_fee, "outputs exceed input by 1 sat").await?;

    let mut extra_output = original.clone();
    extra_output.psbt.0.unsigned_tx.output[0].value -= Amount::ONE_SAT;
    extra_output.psbt.0.unsigned_tx.output.push(TxOut {
        value: Amount::ONE_SAT,
        script_pubkey: destination.clone(),
    });
    extra_output.psbt.0.outputs.push(Default::default());
    rejected(
        &client,
        extra_output,
        "extra output, same recipient and total 500-sat fee",
    )
    .await?;

    // The added native-witness input contributes 1000 sats. Increase the sole
    // payment by exactly that amount so input cardinality is the violated rule,
    // not destination or aggregate fee. Keep both PSBT maps aligned with the tx.
    let mut extra_input = original.clone();
    extra_input.psbt.0.unsigned_tx.input.push(TxIn {
        previous_output: OutPoint::new(Txid::from_byte_array([7; 32]), 0),
        ..Default::default()
    });
    extra_input.psbt.0.inputs.push(bitcoin::psbt::Input {
        witness_utxo: Some(TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: recipient(44),
        }),
        ..Default::default()
    });
    extra_input.psbt.0.unsigned_tx.output[0].value += Amount::from_sat(1_000);
    rejected(
        &client,
        extra_input,
        "extra input, same recipient and total 500-sat fee",
    )
    .await?;

    let mut unexpected_witness = original.clone();
    unexpected_witness.witness.push(1);
    rejected(&client, unexpected_witness, "unexpected predicate witness").await?;

    // This is a commitment-binding check, not a predicate comparison: even a
    // more permissive instance cannot authorize the original funding key.
    let mut substituted = original.clone();
    substituted.instance = contract::instance(MAX_FEE_SATS + 1, &destination)?;
    rejected(
        &client,
        substituted,
        "relaxed fee policy substituted against original funding",
    )
    .await?;

    accepted(
        &client,
        &original,
        "valid 500-sat sweep still signs after all rejections",
    )
    .await?;
    println!(
        "PASS remote compiled safe-withdrawal vault; synthetic funding only, nothing broadcast"
    );
    Ok(())
}
