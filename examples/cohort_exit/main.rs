//! Deterministic research harness. Public fixture keys; never fund these outputs.
mod contract;

use anyhow::{anyhow, bail, ensure, Context as _, Result};
use bitcoin::bip32::Xpriv;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::TapTweak;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TapLeafHash;
use bitcoin::{
    absolute, transaction, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness, XOnlyPublicKey,
};
use contract::{CohortExit, REFUND_BLOCKS};
use emulator_connect::program::{
    prepare_program_request, validate_program_response, ProgramError, ProgramOracle,
    ProgramSigningRequest, ProgramSpendPath,
};
use miniscript::psbt::PsbtExt;
use miniscript::{Interpreter, Miniscript, Tap};
use sapio::contract::abi::object::Object;
use sapio::contract::{Compilable, Context};
use sapio_base::{effects::EffectPath, program::ProgramInstance, LoweringPlan};
use std::sync::Arc;

const USERS: usize = 4;
const DENOMINATION: u64 = 100_000;
const FEE_CAP: u64 = 1_000;
const FEE: u64 = 500;

fn key(tag: u8) -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[tag; 32]).unwrap(),
    )
}

fn recipient(tag: u8) -> ScriptBuf {
    ScriptBuf::new_p2tr(&Secp256k1::new(), key(tag).x_only_public_key().0, None)
}

fn transaction(inputs: Vec<TxIn>, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: inputs,
        output: outputs,
    }
}

fn input(outpoint: OutPoint, sequence: Sequence) -> TxIn {
    TxIn {
        previous_output: outpoint,
        sequence,
        ..Default::default()
    }
}

// Verify real Schnorr signatures, control blocks and executed Miniscript rules.
// This is NOT Bitcoin Core chain/mempool validation or a proof of UTXO existence.
fn verify(tx: &Transaction, prevouts: &[TxOut]) -> Result<()> {
    ensure!(tx.input.len() == prevouts.len(), "prevout count mismatch");
    for (index, (txin, prevout)) in tx.input.iter().zip(prevouts).enumerate() {
        let interpreter = Interpreter::from_txdata(
            &prevout.script_pubkey,
            &txin.script_sig,
            &txin.witness,
            txin.sequence,
            tx.lock_time,
        )?;
        for constraint in interpreter.iter(
            &Secp256k1::verification_only(),
            tx,
            index,
            &Prevouts::All(prevouts),
        ) {
            constraint?;
        }
    }
    Ok(())
}

fn sign_wallet_input(tx: &mut Transaction, prevout: &TxOut, owner: Keypair) -> Result<()> {
    let secp = Secp256k1::new();
    let digest = SighashCache::new(&*tx).taproot_key_spend_signature_hash(
        0,
        &Prevouts::All(&[prevout]),
        TapSighashType::Default,
    )?;
    let signature = secp.sign_schnorr_no_aux_rand(
        &Message::from_digest(digest.to_byte_array()),
        &owner.tap_tweak(&secp, None).to_keypair(),
    );
    tx.input[0].witness = Witness::from_slice(&[signature.as_ref()]);
    verify(tx, std::slice::from_ref(prevout))
}

struct Deposit {
    object: Object,
    funding: Transaction,
    owner: Keypair,
}

fn deposit(instance: ProgramInstance, oracle: &ProgramOracle, index: usize) -> Result<Deposit> {
    let owner = key(11 + index as u8);
    let object = CohortExit::new(instance, oracle.public_root(), owner.x_only_public_key().0)?
        .compile(Context::new(
            Network::Regtest,
            Amount::from_sat(DENOMINATION),
            LoweringPlan::Native,
            EffectPath::try_from("cohort_exit").map_err(|e| anyhow!("effect path: {e:?}"))?,
            Arc::new(Default::default()),
            None,
        ))
        .map_err(|e| anyhow!("compile cohort deposit: {e}"))?;
    let prevout = TxOut {
        value: Amount::from_sat(DENOMINATION + FEE),
        script_pubkey: recipient(1 + index as u8),
    };
    let mut funding = transaction(
        vec![input(
            OutPoint::new(Txid::from_byte_array([1 + index as u8; 32]), 0),
            Sequence::ENABLE_RBF_NO_LOCKTIME,
        )],
        vec![TxOut {
            value: Amount::from_sat(DENOMINATION),
            script_pubkey: ScriptBuf::from(&object.address),
        }],
    );
    sign_wallet_input(&mut funding, &prevout, key(1 + index as u8))?;
    Ok(Deposit {
        object,
        funding,
        owner,
    })
}

fn request(deposit: &Deposit, psbt: Psbt, index: usize) -> Result<ProgramSigningRequest> {
    let requirements = deposit.object.program_requirements()?;
    let mut paths = requirements
        .iter()
        .filter(|r| r.path == ProgramSpendPath::KeyPath);
    let requirement = paths
        .next()
        .context("no program keypath with refund alternative")?;
    ensure!(paths.next().is_none(), "ambiguous program keypath");
    Ok(prepare_program_request(
        &deposit.object,
        requirement,
        psbt,
        index as u32,
        vec![],
    )?)
}

fn batch(deposits: &[Deposit], recipients: &[ScriptBuf]) -> Result<Psbt> {
    let outputs = [1, 3, 0, 2]
        .iter()
        .map(|&i| TxOut {
            value: Amount::from_sat(DENOMINATION - FEE),
            script_pubkey: recipients[i].clone(),
        })
        .collect();
    let inputs = deposits
        .iter()
        .map(|d| {
            input(
                OutPoint::new(d.funding.compute_txid(), 0),
                Sequence::ENABLE_RBF_NO_LOCKTIME,
            )
        })
        .collect();
    let mut psbt = Psbt::from_unsigned_tx(transaction(inputs, outputs))?;
    for (map, deposit) in psbt.inputs.iter_mut().zip(deposits) {
        map.witness_utxo = Some(deposit.funding.output[0].clone());
        deposit
            .object
            .descriptor
            .as_ref()
            .context("missing descriptor")?
            .update_psbt_input(map)?;
    }
    Ok(psbt)
}

fn settle(oracle: &ProgramOracle, deposits: &[Deposit], mut psbt: Psbt) -> Result<Transaction> {
    for (index, deposit) in deposits.iter().enumerate() {
        let request = request(deposit, psbt, index)?;
        let signed = oracle.sign(request.clone())?;
        validate_program_response(&request, &signed, &oracle.public_root())?;
        psbt = signed;
    }
    psbt.finalize_mut(&Secp256k1::verification_only())
        .map_err(|e| anyhow!("finalization: {e:?}"))?;
    let tx = psbt.extract_tx()?;
    let prevouts: Vec<_> = deposits
        .iter()
        .map(|d| d.funding.output[0].clone())
        .collect();
    verify(&tx, &prevouts)?;
    ensure!(tx.input.iter().all(|i| i.witness.len() == 1 && i.witness.iter().next().is_some_and(|s| s.len() == 65)), "settlement revealed a script or lacked SIGHASH_ALL");
    Ok(tx)
}

fn reject(oracle: &ProgramOracle, request: ProgramSigningRequest, label: &str) -> Result<()> {
    match oracle.sign(request) {
        Err(ProgramError::Rejected | ProgramError::Evaluation(_)) => {
            println!("PASS {label}");
            Ok(())
        }
        Err(error) => {
            bail!("{label}: unexpected structural error instead of predicate refusal: {error}")
        }
        Ok(_) => bail!("{label}: unsafe request was signed"),
    }
}

fn refund(deposit: &Deposit, sequence: Sequence, signing_key: Keypair) -> Result<Transaction> {
    let mut metadata = bitcoin::psbt::Input::default();
    deposit
        .object
        .descriptor
        .as_ref()
        .context("missing descriptor")?
        .update_psbt_input(&mut metadata)?;
    let owner = deposit.owner.x_only_public_key().0;
    let mut refund_leaf = None;
    for (control, (script, version)) in &metadata.tap_scripts {
        let leaf = Miniscript::<XOnlyPublicKey, Tap>::decode(script)?;
        if leaf.iter_pk().any(|pk| pk == owner) {
            ensure!(refund_leaf.is_none(), "ambiguous owner refund leaf");
            refund_leaf = Some((control, script, *version));
        }
    }
    let (control, script, version) = refund_leaf.context("owner refund absent")?;
    let prevout = &deposit.funding.output[0];
    let mut tx = transaction(
        vec![input(
            OutPoint::new(deposit.funding.compute_txid(), 0),
            sequence,
        )],
        vec![TxOut {
            value: Amount::from_sat(DENOMINATION - FEE),
            script_pubkey: recipient(41),
        }],
    );
    let leaf_hash = TapLeafHash::from_script(script, version);
    let digest = SighashCache::new(&tx).taproot_script_spend_signature_hash(
        0,
        &Prevouts::All(&[prevout]),
        leaf_hash,
        TapSighashType::Default,
    )?;
    let signature = Secp256k1::new()
        .sign_schnorr_no_aux_rand(&Message::from_digest(digest.to_byte_array()), &signing_key);
    tx.input[0].witness =
        Witness::from_slice(&[signature.as_ref(), script.as_bytes(), &control.serialize()]);
    Ok(tx)
}

// A deliberately weak chain observer sees equal amounts/types, but no address
// labels, setup transcript, timing, later spends, or colluding participants.
// Count bijections consistent with JUST that model. Not an anonymity proof.
fn candidate_mappings(inputs: &[TxOut], outputs: &[TxOut], known: usize) -> u64 {
    fn visit(inputs: &[TxOut], outputs: &[TxOut], index: usize, used: u32) -> u64 {
        if index == inputs.len() {
            return 1;
        }
        outputs
            .iter()
            .enumerate()
            .filter(|(j, o)| {
                used & (1 << j) == 0
                    && inputs[index].script_pubkey.is_p2tr()
                    && o.script_pubkey.is_p2tr()
                    && inputs[index].value.to_sat().checked_sub(o.value.to_sat()) == Some(FEE)
            })
            .map(|(j, _)| visit(inputs, outputs, index + 1, used | (1 << j)))
            .sum()
    }
    // Known pairs have first been relabelled to the leading diagonal. That is
    // valid only because this fixture has identical amounts and script types.
    visit(&inputs[known..], &outputs[known..], 0, 0)
}

fn main() -> Result<()> {
    // Public, reproducible fixture root; uses the exact deployment registry.
    let oracle =
        sapio_tee::deployment::program_oracle(Xpriv::new_master(Network::Regtest, &[0xc7; 32])?)?;
    let recipients: Vec<_> = (21..21 + USERS as u8).map(recipient).collect();
    let instance = contract::instance([0xce; 32], DENOMINATION, FEE_CAP, recipients.clone())?;
    let mut deposits: Vec<_> = (0..USERS)
        .map(|i| deposit(instance.clone(), &oracle, i))
        .collect::<Result<_>>()?;
    deposits.swap(0, 2);
    deposits.swap(1, 3);
    ensure!(
        deposits.iter().enumerate().all(|(i, d)| deposits[..i]
            .iter()
            .all(|p| p.funding.output[0].script_pubkey != d.funding.output[0].script_pubkey)),
        "reused deposit address"
    );
    let original = batch(&deposits, &recipients)?;
    let settled = settle(&oracle, &deposits, original.clone())?;
    println!("PASS four Sapio-compiled deposits settle with verified keypath signatures and no depositor signatures after funding");

    let mut maximum_fee = original.clone();
    for output in &mut maximum_fee.unsigned_tx.output {
        output.value = Amount::from_sat(DENOMINATION - FEE_CAP);
    }
    settle(&oracle, &deposits, maximum_fee)?;
    let mut reordered = original.clone();
    reordered.unsigned_tx.output.reverse();
    settle(&oracle, &deposits, reordered)?;
    println!("PASS bounded equal fee bump and reordered payouts");

    let original_request = request(&deposits[0], original.clone(), 0)?;
    let mut redirected = original_request.clone();
    redirected.psbt.0.unsigned_tx.output[0].script_pubkey = recipient(60);
    reject(&oracle, redirected, "redirected payout rejected")?;
    let mut duplicate = original_request.clone();
    duplicate.psbt.0.unsigned_tx.output[1] = duplicate.psbt.0.unsigned_tx.output[0].clone();
    reject(
        &oracle,
        duplicate,
        "duplicate payout / missing cohort member rejected",
    )?;
    let mut tagged = original_request.clone();
    tagged.psbt.0.unsigned_tx.output[0].value += Amount::ONE_SAT;
    tagged.psbt.0.unsigned_tx.output[1].value -= Amount::ONE_SAT;
    reject(
        &oracle,
        tagged,
        "one-satoshi amount tagging rejected at unchanged total fee",
    )?;
    let mut excessive = original_request.clone();
    for output in &mut excessive.psbt.0.unsigned_tx.output {
        output.value = Amount::from_sat(DENOMINATION - FEE_CAP - 1);
    }
    reject(
        &oracle,
        excessive,
        "fee cap exceeded uniformly by one satoshi rejected",
    )?;
    let mut negative = original_request.clone();
    for output in &mut negative.psbt.0.unsigned_tx.output {
        output.value = Amount::from_sat(DENOMINATION + 1);
    }
    reject(&oracle, negative, "negative fee rejected")?;
    let mut missing = original_request.clone();
    missing.psbt.0.unsigned_tx.output.pop();
    missing.psbt.0.outputs.pop();
    reject(&oracle, missing, "incomplete payout roster rejected")?;
    let mut incomplete = original_request.clone();
    incomplete.psbt.0.unsigned_tx.input.pop();
    incomplete.psbt.0.inputs.pop();
    reject(&oracle, incomplete, "incomplete funding cohort rejected")?;
    let mut reused = original_request.clone();
    reused.psbt.0.unsigned_tx.input[1].previous_output =
        reused.psbt.0.unsigned_tx.input[0].previous_output;
    reject(&oracle, reused, "reused input outpoint rejected")?;
    let mut witness = original_request.clone();
    witness.witness.push(1);
    reject(&oracle, witness, "unexpected evidence rejected")?;
    let mut unequal = original_request.clone();
    unequal.psbt.0.inputs[1]
        .witness_utxo
        .as_mut()
        .unwrap()
        .value += Amount::ONE_SAT;
    reject(&oracle, unequal, "unequal input denomination rejected")?;

    let mut substituted = original_request.clone();
    substituted.instance =
        contract::instance([0xce; 32], DENOMINATION, FEE_CAP + 1, recipients.clone())?;
    ensure!(
        oracle.sign(substituted).is_err(),
        "substituted policy signed original funding"
    );
    println!("PASS policy substitution cannot authorize original deposit");

    // The oracle is stateless, not a UTXO authenticator. A fake foreign prevout
    // can be signed, but cannot produce a valid SIGHASH_ALL on the actual coin.
    let mut lied = original_request.clone();
    lied.psbt.0.inputs[1]
        .witness_utxo
        .as_mut()
        .unwrap()
        .script_pubkey = recipient(61);
    let signed_lie = oracle.sign(lied.clone())?;
    validate_program_response(&lied, &signed_lie, &oracle.public_root())?;
    let mut actual_context = signed_lie.clone();
    actual_context.inputs[1].witness_utxo = original.inputs[1].witness_utxo.clone();
    ensure!(
        validate_program_response(&original_request, &actual_context, &oracle.public_root())
            .is_err(),
        "foreign-prevout lie produced a signature valid for the real inputs"
    );
    println!("PASS forged foreign prevout is not authenticated by oracle; signature fails in real context");

    let mut refund_vbytes = 0;
    for deposit in &deposits {
        let prevout = std::slice::from_ref(&deposit.funding.output[0]);
        let recovered = refund(deposit, Sequence::from_height(REFUND_BLOCKS), deposit.owner)?;
        verify(&recovered, prevout)?;
        refund_vbytes = recovered.vsize();
        let early = refund(
            deposit,
            Sequence::from_height(REFUND_BLOCKS - 1),
            deposit.owner,
        )?;
        ensure!(verify(&early, prevout).is_err(), "CSV lower bound bypassed");
        let disabled = refund(deposit, Sequence::ENABLE_RBF_NO_LOCKTIME, deposit.owner)?;
        ensure!(verify(&disabled, prevout).is_err(), "disabled CSV accepted");
        let impostor = refund(deposit, Sequence::from_height(REFUND_BLOCKS), key(62))?;
        ensure!(
            verify(&impostor, prevout).is_err(),
            "non-owner refund accepted"
        );
    }
    println!("PASS all native owner refunds verify without oracle; short/disabled CSV and wrong keys fail (chain age not simulated)");

    let mut received = transaction(
        vec![input(
            OutPoint::new(settled.compute_txid(), 0),
            Sequence::ENABLE_RBF_NO_LOCKTIME,
        )],
        vec![TxOut {
            value: settled.output[0].value - Amount::from_sat(FEE),
            script_pubkey: recipient(63),
        }],
    );
    sign_wallet_input(&mut received, &settled.output[0], key(22))?;
    println!("PASS recipient can spend received payout with its own wallet key");
    ensure!(
        settle(&oracle, &deposits, original.clone())? == settled,
        "deterministic replay changed settlement"
    );

    let prevouts: Vec<_> = deposits
        .iter()
        .map(|d| d.funding.output[0].clone())
        .collect();
    let mappings = candidate_mappings(&prevouts, &settled.output, 0);
    let colluding = candidate_mappings(&prevouts, &settled.output, 2);
    ensure!(
        mappings == 24 && colluding == 2 && candidate_mappings(&prevouts, &settled.output, 3) == 1,
        "observer model changed"
    );
    let deposit_vbytes: usize = deposits.iter().map(|d| d.funding.vsize()).sum();
    println!("MODEL amount/type-only observer: {mappings} bijections; two known pairs: {colluding}; three known pairs: 1. Not measured real-world anonymity.");
    println!("LIMITS plaintext setup/operator sees associations; Sybils, timing, address reuse and later consolidation can destroy privacy; TEE honesty required; refund/settlement race after maturity; synthetic UTXOs only.");
    println!(
        "FIXTURE settlement_txid={} wasm_sha256={}",
        settled.compute_txid(),
        sha256::Hash::hash(instance.program())
    );
    println!(
        "METRIC lifecycle_vbytes_per_user={:.2}",
        (deposit_vbytes + settled.vsize()) as f64 / USERS as f64
    );
    println!("METRIC settlement_vbytes={}", settled.vsize());
    println!("METRIC deposit_vbytes={deposit_vbytes}");
    println!("METRIC refund_vbytes={refund_vbytes}");
    println!("METRIC model_candidate_mappings={mappings}");
    println!("METRIC model_mappings_two_known={colluding}");
    println!("METRIC wasm_bytes={}", instance.program().len());
    Ok(())
}
