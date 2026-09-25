use super::tests::{context, wallet_call};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bitcoin::bip32::{Xpriv, Xpub};
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::TapSighashType;
use bitcoin::taproot::ControlBlock;
use bitcoin::{Address, Amount, Network, ScriptBuf, Transaction, Txid};
use passkey_client::{contract, WalletContext};
use serde_json::{json, Value};

const SECRETS: [[u8; 32]; 2] = [[13; 32], [14; 32]];

fn fixture() -> (WalletContext, Value) {
    let secp = Secp256k1::new();
    let root = Xpriv::new_master(Network::Regtest, &[41; 32]).unwrap();
    // The core has no oracle client or transport; recovery is entirely local.
    let app = context(Xpub::from_priv(&secp, &root));
    let credential = p256::ecdsa::SigningKey::from_bytes((&[7; 32]).into()).unwrap();
    let recipient = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([3; 20]));
    let input = json!({
        "public_key": hex::encode(credential.verifying_key().to_encoded_point(true)),
        "recovery_keys": SECRETS.map(|key| hex::encode(passkey_recovery::public_key(&key).unwrap())),
        "funding": {"txid": Txid::from_byte_array([2; 32]), "vout": 0, "value_sats": 100_000},
        "recipient": Address::from_script(&recipient, Network::Regtest).unwrap().to_string(),
        "amount_sats": 80_000, "fee_sats": 1_000, "path": "recovery",
    });
    (app, input)
}

fn prepared(app: &WalletContext, input: &Value) -> (Psbt, contract::Recovery, [u8; 32]) {
    let prepared = wallet_call(app, "prepare", input.clone()).unwrap();
    let psbt =
        Psbt::deserialize(&STANDARD.decode(prepared["psbt"].as_str().unwrap()).unwrap()).unwrap();
    let recovery =
        contract::recovery(&SECRETS.map(|key| passkey_recovery::public_key(&key).unwrap()))
            .unwrap();
    let digest = hex::decode(prepared["recovery"]["sighash"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    (psbt, recovery, digest)
}

fn submission(input: &Value, psbt: &Psbt, signature: &[u8; 64]) -> Value {
    json!({
        "public_key": input["public_key"], "recovery_keys": input["recovery_keys"],
        "psbt": STANDARD.encode(psbt.serialize()), "signature": hex::encode(signature),
    })
}

#[test]
fn enrollment_rejects_single_key_disguised_as_two_signers() {
    let keys = SECRETS.map(|key| passkey_recovery::public_key(&key).unwrap());
    assert!(contract::recovery(&[keys[0], keys[0]]).is_err());
    let mut negated = keys[0];
    negated[0] ^= 1;
    assert!(contract::recovery(&[keys[0], negated]).is_err());
    let mut invalid = keys[1];
    invalid[0] = 4;
    assert!(contract::recovery(&[keys[0], invalid]).is_err());

    // Role ordering must not create a different funded wallet on restore.
    let (app, input) = fixture();
    let wallet =
        json!({"public_key": input["public_key"], "recovery_keys": input["recovery_keys"]});
    let first = wallet_call(&app, "wallet", wallet.clone()).unwrap();
    let mut reversed = wallet;
    reversed["recovery_keys"].as_array_mut().unwrap().reverse();
    let second = wallet_call(&app, "wallet", reversed).unwrap();
    assert_eq!(first["address"], second["address"]);
}

#[test]
fn two_signers_recover_without_oracle_or_passkey_but_one_cannot() {
    let (app, input) = fixture();
    let (psbt, recovery, digest) = prepared(&app, &input);
    let secret = SecretKey::from_slice(&SECRETS[0]).unwrap();
    let secp = Secp256k1::new();
    let single = secp
        .sign_schnorr_no_aux_rand(
            &Message::from_digest(digest),
            &Keypair::from_secret_key(&secp, &secret),
        )
        .serialize();
    assert!(wallet_call(
        &app,
        "finalize_recovery",
        submission(&input, &psbt, &single)
    )
    .is_err());
    assert!(passkey_recovery::sign(
        &[SECRETS[0], SECRETS[0]],
        &recovery.public_keys,
        &digest,
        &[[31; 32], [47; 32]],
    )
    .is_none());

    // The supplied secrets can be in a different order from the canonical keys.
    let signature = passkey_recovery::sign(
        &[SECRETS[1], SECRETS[0]],
        &recovery.public_keys,
        &digest,
        &[[31; 32], [47; 32]],
    )
    .unwrap();
    let response = wallet_call(
        &app,
        "finalize_recovery",
        submission(&input, &psbt, &signature),
    )
    .unwrap();
    let transaction: Transaction =
        deserialize(&hex::decode(response["transaction_hex"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(transaction.compute_txid(), psbt.unsigned_tx.compute_txid());
    assert_eq!(response["fee_sats"], 1_000);
    let witness: Vec<&[u8]> = transaction.input[0].witness.iter().collect();
    assert_eq!(witness.len(), 3);
    assert_eq!(&witness[0][..64], &signature);
    assert_eq!(witness[0][64], TapSighashType::All as u8);
    assert_eq!(witness[1], recovery.script.as_bytes());
    let control = ControlBlock::decode(witness[2]).unwrap();
    let prevout = psbt.inputs[0].witness_utxo.as_ref().unwrap();
    let output_key =
        bitcoin::XOnlyPublicKey::from_slice(&prevout.script_pubkey.as_bytes()[2..]).unwrap();
    assert!(control.verify_taproot_commitment(&secp, output_key, &recovery.script));
}

#[test]
fn recovery_signature_cannot_authorize_changed_payment_or_prevout() {
    let (app, input) = fixture();
    let (psbt, recovery, digest) = prepared(&app, &input);
    let signature = passkey_recovery::sign(
        &SECRETS,
        &recovery.public_keys,
        &digest,
        &[[51; 32], [67; 32]],
    )
    .unwrap();
    let mut redirected = psbt.clone();
    redirected.unsigned_tx.output[0].script_pubkey =
        ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([99; 20]));
    let mut inflated = psbt.clone();
    inflated.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(110_000);
    let mut changed_fee = psbt.clone();
    changed_fee.unsigned_tx.output[0].value = Amount::from_sat(79_000);
    let mut wrong_leaf = psbt.clone();
    wrong_leaf.inputs[0].tap_scripts.clear();
    let mut wrong_outpoint = psbt.clone();
    wrong_outpoint.unsigned_tx.input[0].previous_output.vout = 1;
    let mut wrong_sighash = psbt.clone();
    wrong_sighash.inputs[0].sighash_type = Some(TapSighashType::Default.into());
    for altered in [
        redirected,
        inflated,
        changed_fee,
        wrong_leaf,
        wrong_outpoint,
        wrong_sighash,
    ] {
        assert!(wallet_call(
            &app,
            "finalize_recovery",
            submission(&input, &altered, &signature)
        )
        .is_err());
    }
}
