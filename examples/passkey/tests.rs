use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bitcoin::bip32::{Xpriv, Xpub};
use bitcoin::blockdata::opcodes::all::OP_CHECKSIG;
use bitcoin::blockdata::script::Builder;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::sighash::TapSighashType;
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::{Address, Amount, Network, ScriptBuf, Transaction, Txid};
use emulator_connect::program::{
    validate_program_response, ProgramOracle, ProgramSigningRequest, ProgramSpendPath, PSBT,
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use passkey_client::{
    contract,
    wire::{OracleResponse, WirePsbt},
    Call, WalletContext,
};
use serde_json::{json, Value};

const RP_ID: &str = "localhost";
const ORIGIN: &str = "http://localhost:8080";

pub(super) fn context(root: Xpub) -> WalletContext {
    serde_json::from_value(json!({
        "identity": {
            "protocol": "sapio-tee/program-oracle/1", "mode": "local-dev", "xpub": root,
            "settings": null, "signing": sapio_tee::deployment::program_profile(),
        },
        "origin": ORIGIN, "rp_id": RP_ID, "allow_local_dev": true,
    }))
    .unwrap()
}

pub(super) fn wallet_call(context: &WalletContext, operation: &str, body: Value) -> Result<Value> {
    passkey_client::call(Call {
        context: context.clone(),
        operation: operation.into(),
        body,
    })
}

struct Fixture {
    oracle: ProgramOracle,
    credential: SigningKey,
    request: ProgramSigningRequest,
}

fn recovery_keys() -> [[u8; 33]; 2] {
    [
        passkey_recovery::public_key(&[9; 32]).unwrap(),
        passkey_recovery::public_key(&[10; 32]).unwrap(),
    ]
}

fn fixture() -> Fixture {
    let oracle = ProgramOracle::new(
        Xpriv::new_master(Network::Regtest, &[42; 32]).unwrap(),
        vec![],
    )
    .unwrap();
    let credential = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let public = credential.verifying_key().to_encoded_point(true);
    let recovery = contract::recovery(&recovery_keys()).unwrap();
    let instance = contract::instance(
        Network::Regtest,
        RP_ID,
        ORIGIN,
        public.as_bytes(),
        &recovery,
    )
    .unwrap();
    let recipient = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([3; 20]));
    let prepared = wallet_call(&context(oracle.public_root()), "prepare", json!({
        "public_key": hex::encode(public),
        "recovery_keys": recovery_keys().map(hex::encode),
        "funding": {"txid": Txid::from_byte_array([2; 32]), "vout": 0, "value_sats": 100_000},
        "recipient": Address::from_script(&recipient, Network::Regtest).unwrap().to_string(),
        "amount_sats": 99_000, "fee_sats": 1_000, "path": "passkey", "nonce": hex::encode([23; 32]),
    })).unwrap();
    let psbt =
        Psbt::deserialize(&STANDARD.decode(prepared["psbt"].as_str().unwrap()).unwrap()).unwrap();
    Fixture {
        oracle,
        credential,
        request: ProgramSigningRequest {
            instance,
            psbt: PSBT(psbt),
            input_index: 0,
            witness: Vec::new(),
            path: ProgramSpendPath::KeyPath,
        },
    }
}

fn client_data(request: &ProgramSigningRequest) -> Value {
    let challenge = contract::challenge(
        request.instance.parameters(),
        &contract::signed_view(&request.psbt.0, request.input_index).unwrap(),
        &[23; 32],
    );
    json!({"type":"webauthn.get", "challenge":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge), "origin":ORIGIN, "crossOrigin":false})
}

fn assertion(key: &SigningKey, client: &[u8], rp_id: &str, flags: u8) -> Vec<u8> {
    let mut auth = contract::hash(rp_id.as_bytes()).to_vec();
    auth.push(flags);
    auth.extend_from_slice(&0u32.to_be_bytes()); // Synced authenticators may not count.
    let mut message = auth.clone();
    message.extend_from_slice(&contract::hash(client));
    let signature: Signature = key.sign(&message);
    contract::witness(&[23; 32], &auth, client, signature.to_der().as_bytes()).unwrap()
}

fn approve(key: &SigningKey, request: &mut ProgramSigningRequest) {
    request.witness = assertion(
        key,
        &serde_json::to_vec(&client_data(request)).unwrap(),
        RP_ID,
        5,
    );
}

fn accepted(oracle: &ProgramOracle, request: &ProgramSigningRequest) {
    let response = oracle.sign(request.clone()).unwrap();
    validate_program_response(request, &response, &oracle.public_root()).unwrap();
}

fn rejected(oracle: &ProgramOracle, request: ProgramSigningRequest, label: &str) {
    assert!(
        oracle.sign(request).is_err(),
        "unauthorized signature: {label}"
    );
}

#[test]
fn assertion_binds_payment_prevout_fee_and_selected_input() {
    let mut f = fixture();
    approve(&f.credential, &mut f.request);
    accepted(&f.oracle, &f.request);
    // Stateless reauthorization is deliberately possible only for the same spend.
    accepted(&f.oracle, &f.request);

    let mut changed = f.request.clone();
    changed.psbt.0.unsigned_tx.output[0].value -= Amount::ONE_SAT;
    rejected(&f.oracle, changed, "fee/amount changed after approval");
    let mut changed = f.request.clone();
    changed.psbt.0.unsigned_tx.output[0].script_pubkey =
        ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([4; 20]));
    rejected(&f.oracle, changed, "recipient changed after approval");
    let mut changed = f.request.clone();
    changed.psbt.0.unsigned_tx.input[0].previous_output.vout = 1;
    rejected(&f.oracle, changed, "approval reused for another UTXO");
    let mut changed = f.request.clone();
    changed.psbt.0.inputs[0]
        .witness_utxo
        .as_mut()
        .unwrap()
        .value += Amount::ONE_SAT;
    rejected(&f.oracle, changed, "input amount changed after approval");

    let mut multi = f.request.clone();
    let mut other_input = multi.psbt.0.unsigned_tx.input[0].clone();
    other_input.previous_output.vout = 1;
    multi.psbt.0.unsigned_tx.input.push(other_input);
    multi.psbt.0.inputs.push(multi.psbt.0.inputs[0].clone());
    multi.psbt.0.unsigned_tx.output[0].value += Amount::from_sat(100_000);
    approve(&f.credential, &mut multi);
    accepted(&f.oracle, &multi);
    let mut changed = multi.clone();
    changed.psbt.0.unsigned_tx.input[1].previous_output.vout = 2;
    rejected(
        &f.oracle,
        changed,
        "non-selected input changed after approval",
    );
    multi.input_index = 1;
    rejected(
        &f.oracle,
        multi.clone(),
        "approval reused for another selected input",
    );
    approve(&f.credential, &mut multi);
    accepted(&f.oracle, &multi);
}

#[test]
fn webauthn_context_and_credential_are_enforced_inside_guest() {
    let f = fixture();
    let original = client_data(&f.request);
    for (field, value) in [
        ("type", json!("webauthn.create")),
        ("origin", json!("https://attacker.example")),
        (
            "challenge",
            json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ),
        ("crossOrigin", json!(true)),
        ("topOrigin", json!(ORIGIN)),
        ("topOrigin", json!(null)),
    ] {
        let mut client = original.clone();
        client[field] = value;
        let mut request = f.request.clone();
        request.witness = assertion(
            &f.credential,
            &serde_json::to_vec(&client).unwrap(),
            RP_ID,
            5,
        );
        rejected(&f.oracle, request, field);
    }
    let client = serde_json::to_vec(&original).unwrap();
    for (flags, label) in [
        (1, "UV missing"),
        (4, "UP missing"),
        (0x15, "BS without BE"),
        (0x45, "attestation data flag"),
        (0x85, "extensions flag"),
    ] {
        let mut request = f.request.clone();
        request.witness = assertion(&f.credential, &client, RP_ID, flags);
        rejected(&f.oracle, request, label);
    }
    let mut request = f.request.clone();
    request.witness = assertion(&f.credential, &client, "attacker.example", 5);
    rejected(&f.oracle, request, "RP ID mismatch");
    let wrong_key = SigningKey::from_bytes((&[8u8; 32]).into()).unwrap();
    let mut request = f.request.clone();
    request.witness = assertion(&wrong_key, &client, RP_ID, 5);
    rejected(&f.oracle, request, "different passkey");
    let mut synced = f.request.clone();
    synced.witness = assertion(&f.credential, &client, RP_ID, 0x1d);
    accepted(&f.oracle, &synced);
}

#[test]
fn original_json_bytes_and_strict_framing_are_authenticated() {
    let f = fixture();
    let original = serde_json::to_string(&client_data(&f.request)).unwrap();
    // Legal JSON escapes are interpreted, but the ORIGINAL bytes are signed.
    let escaped = original.replace(ORIGIN, "http:\\/\\/localhost:8080");
    let mut request = f.request.clone();
    request.witness = assertion(&f.credential, escaped.as_bytes(), RP_ID, 5);
    accepted(&f.oracle, &request);
    // Additional client-data members are part of WebAuthn's extensible format.
    // Chromium deliberately injects one sometimes; it is still authenticated.
    let mut extended = client_data(&f.request);
    extended["futureClientData"] = json!({"nested": [true, 7, "signed extra bytes"]});
    let mut request = f.request.clone();
    request.witness = assertion(
        &f.credential,
        &serde_json::to_vec(&extended).unwrap(),
        RP_ID,
        5,
    );
    accepted(&f.oracle, &request);
    let duplicate = format!(
        "{},\"origin\":\"{ORIGIN}\"}}",
        &original[..original.len() - 1]
    );
    let mut request = f.request.clone();
    request.witness = assertion(&f.credential, duplicate.as_bytes(), RP_ID, 5);
    rejected(&f.oracle, request, "duplicate JSON field");
    let mut valid = f.request.clone();
    approve(&f.credential, &mut valid);
    let mut modified = valid.clone();
    *modified.witness.last_mut().unwrap() ^= 1;
    rejected(&f.oracle, modified, "modified DER signature");
    let mut modified = valid.clone();
    modified.witness.pop();
    rejected(&f.oracle, modified, "truncated witness");
    let mut modified = valid.clone();
    modified.witness.push(0);
    rejected(&f.oracle, modified, "trailing witness data");
    let mut modified = valid.clone();
    modified.witness[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
    rejected(&f.oracle, modified, "out-of-bounds length");
    let mut empty = f.request.clone();
    empty.witness.clear();
    rejected(&f.oracle, empty, "missing passkey assertion");
    accepted(&f.oracle, &valid);
}

#[test]
fn policy_substitution_cannot_rebind_original_funding() {
    let f = fixture();
    let mut valid = f.request.clone();
    approve(&f.credential, &mut valid);
    let other = SigningKey::from_bytes((&[8u8; 32]).into()).unwrap();
    let mut substituted = valid.clone();
    substituted.instance = contract::instance(
        Network::Regtest,
        RP_ID,
        ORIGIN,
        other.verifying_key().to_encoded_point(true).as_bytes(),
        &contract::recovery(&recovery_keys()).unwrap(),
    )
    .unwrap();
    approve(&other, &mut substituted);
    rejected(
        &f.oracle,
        substituted,
        "substituted policy against original funding",
    );

    let public = f.credential.verifying_key().to_encoded_point(true);
    let mut changed_keys = recovery_keys();
    changed_keys[1] = passkey_recovery::public_key(&[11; 32]).unwrap();
    let mut substituted = valid.clone();
    substituted.instance = contract::instance(
        Network::Regtest,
        RP_ID,
        ORIGIN,
        public.as_bytes(),
        &contract::recovery(&changed_keys).unwrap(),
    )
    .unwrap();
    approve(&f.credential, &mut substituted);
    rejected(
        &f.oracle,
        substituted,
        "substituted recovery commitment against original funding",
    );
}

#[test]
fn uncommitted_or_missing_recovery_tree_is_rejected_inside_guest() {
    let f = fixture();
    let key = contract::derive_public_key(&f.request.instance, &f.oracle.public_root()).unwrap();
    let wrong_leaf = Builder::new()
        .push_slice(key.serialize())
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let wrong_tree = TaprootBuilder::new()
        .add_leaf(0, wrong_leaf.clone())
        .unwrap()
        .finalize(&Secp256k1::new(), key)
        .unwrap();
    for (root, label) in [
        (None, "missing recovery tree"),
        (wrong_tree.merkle_root(), "uncommitted recovery tree"),
    ] {
        let mut request = f.request.clone();
        request.psbt.0.inputs[0]
            .witness_utxo
            .as_mut()
            .unwrap()
            .script_pubkey = ScriptBuf::new_p2tr(&Secp256k1::verification_only(), key, root);
        request.psbt.0.inputs[0].tap_merkle_root = root;
        // Host metadata matches this output and the assertion is valid. Only
        // the guest's funding-root check distinguishes it from enrolled funding.
        approve(&f.credential, &mut request);
        rejected(&f.oracle, request, label);
    }
    let mut script_path = f.request.clone();
    script_path.psbt.0.inputs[0]
        .witness_utxo
        .as_mut()
        .unwrap()
        .script_pubkey = ScriptBuf::new_p2tr_tweaked(wrong_tree.output_key());
    script_path.psbt.0.inputs[0].tap_merkle_root = wrong_tree.merkle_root();
    let control = wrong_tree
        .control_block(&(wrong_leaf.clone(), LeafVersion::TapScript))
        .unwrap();
    script_path.path = ProgramSpendPath::ScriptPath(TapLeafHash::from_script(
        &wrong_leaf,
        LeafVersion::TapScript,
    ));
    script_path.psbt.0.inputs[0]
        .tap_scripts
        .insert(control, (wrong_leaf, LeafVersion::TapScript));
    approve(&f.credential, &mut script_path);
    rejected(
        &f.oracle,
        script_path,
        "uncommitted script-path alternative",
    );
}

#[test]
fn committed_recovery_tree_preserves_normal_passkey_keypath() {
    let mut f = fixture();
    let recovery = contract::recovery(&recovery_keys()).unwrap();
    let key = contract::derive_public_key(&f.request.instance, &f.oracle.public_root()).unwrap();
    let spend = TaprootBuilder::new()
        .add_leaf(0, recovery.script.clone())
        .unwrap()
        .finalize(&Secp256k1::new(), key)
        .unwrap();
    let control = spend
        .control_block(&(recovery.script.clone(), LeafVersion::TapScript))
        .unwrap();
    f.request.psbt.0.inputs[0]
        .tap_scripts
        .insert(control, (recovery.script, LeafVersion::TapScript));
    approve(&f.credential, &mut f.request);
    accepted(&f.oracle, &f.request);
}

fn browser_request(f: &Fixture) -> Value {
    let client = serde_json::to_vec(&client_data(&f.request)).unwrap();
    let mut auth = contract::hash(RP_ID.as_bytes()).to_vec();
    auth.push(5);
    auth.extend_from_slice(&0u32.to_be_bytes());
    let mut message = auth.clone();
    message.extend_from_slice(&contract::hash(&client));
    let signature: Signature = f.credential.sign(&message);
    wallet_call(
        &context(f.oracle.public_root()),
        "request",
        json!({
            "public_key": hex::encode(f.credential.verifying_key().to_encoded_point(true)),
            "recovery_keys": recovery_keys().map(hex::encode),
            "psbt": STANDARD.encode(f.request.psbt.0.serialize()), "nonce": hex::encode([23; 32]),
            "authenticator_data": hex::encode(auth), "client_data_json": hex::encode(client),
            "signature": hex::encode(signature.to_der()),
        }),
    )
    .unwrap()
}

#[test]
fn browser_checks_exact_original_psbt_and_pinned_output_signature() {
    let f = fixture();
    let app = context(f.oracle.public_root());
    let request = browser_request(&f);
    // The browser envelope must be accepted by the actual upstream request and
    // oracle, not a mock of either wire encoding or signature production.
    let native: ProgramSigningRequest =
        serde_json::from_value(request["SignProgramV1"].clone()).unwrap();
    let signed = f.oracle.sign(native).unwrap();
    let finalize = |signed: Psbt| {
        wallet_call(
            &app,
            "finalize_passkey",
            json!({
                "request": request,
                "response": OracleResponse::SignedV1(WirePsbt(signed)),
            }),
        )
    };
    let finalized = finalize(signed.clone()).unwrap();
    let transaction: Transaction =
        deserialize(&hex::decode(finalized["transaction_hex"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(
        transaction.compute_txid(),
        f.request.psbt.0.unsigned_tx.compute_txid()
    );
    assert_eq!(finalized["fee_sats"], 1_000);
    let witness: Vec<_> = transaction.input[0].witness.iter().collect();
    assert_eq!(witness.len(), 1);
    assert_eq!(witness[0].len(), 65);
    assert_eq!(witness[0][64], TapSighashType::All as u8);

    let mut payment = signed.clone();
    payment.unsigned_tx.output[0].value -= Amount::ONE_SAT;
    let mut prevout = signed.clone();
    prevout.inputs[0].witness_utxo.as_mut().unwrap().value += Amount::ONE_SAT;
    let mut tree = signed.clone();
    tree.inputs[0].tap_merkle_root = None;
    let mut key = signed.clone();
    key.inputs[0].tap_internal_key = None;
    let mut signature = signed.clone();
    signature.inputs[0].tap_key_sig.as_mut().unwrap().signature =
        bitcoin::secp256k1::schnorr::Signature::from_slice(&[0; 64]).unwrap();
    let mut default_sighash = signed.clone();
    default_sighash.inputs[0]
        .tap_key_sig
        .as_mut()
        .unwrap()
        .sighash_type = TapSighashType::Default;
    let mut metadata = signed.clone();
    metadata.unknown.insert(
        bitcoin::psbt::raw::Key {
            type_value: 0xee,
            key: vec![1],
        },
        vec![2],
    );
    let mut already_finalized = signed.clone();
    already_finalized.inputs[0].final_script_witness = Some(bitcoin::Witness::new());
    for altered in [
        payment,
        prevout,
        tree,
        key,
        signature,
        default_sighash,
        metadata,
        already_finalized,
    ] {
        assert!(finalize(altered).is_err());
    }
    let other_root = Xpub::from_priv(
        &Secp256k1::new(),
        &Xpriv::new_master(Network::Regtest, &[99; 32]).unwrap(),
    );
    assert!(wallet_call(
        &context(other_root),
        "finalize_passkey",
        json!({
            "request": request, "response": OracleResponse::SignedV1(WirePsbt(signed)),
        })
    )
    .is_err());
}

#[test]
fn browser_finalization_rejects_wire_smuggling_and_policy_substitution() {
    let f = fixture();
    let app = context(f.oracle.public_root());
    let request = browser_request(&f);
    let native: ProgramSigningRequest =
        serde_json::from_value(request["SignProgramV1"].clone()).unwrap();
    let signed = f.oracle.sign(native).unwrap();
    let response = serde_json::to_value(OracleResponse::SignedV1(WirePsbt(signed))).unwrap();
    let mut trailing = response.clone();
    trailing["SignedV1"].as_array_mut().unwrap().push(json!(0));
    let mut truncated = response.clone();
    truncated["SignedV1"].as_array_mut().unwrap().pop();
    let mut oversized = response.clone();
    for index in 0..4 {
        oversized["SignedV1"][index] = json!(255);
    }
    for response in [trailing, truncated, oversized, json!({"SignedV0": []})] {
        assert!(wallet_call(
            &app,
            "finalize_passkey",
            json!({"request": request, "response": response})
        )
        .is_err());
    }
    let mut substituted = request.clone();
    substituted["SignProgramV1"]["instance"]["program"][0] = json!(255);
    assert!(wallet_call(
        &app,
        "finalize_passkey",
        json!({"request": substituted, "response": response})
    )
    .is_err());
    let mut foreign_origin = app.clone();
    foreign_origin.origin = "https://wallet.example".into();
    foreign_origin.rp_id = "wallet.example".into();
    assert!(wallet_call(
        &foreign_origin,
        "finalize_passkey",
        json!({"request": request, "response": response})
    )
    .is_err());
    let error = wallet_call(
        &app,
        "finalize_passkey",
        json!({
            "request": request, "response": {"RejectedV1": "passkey assertion rejected"},
        }),
    )
    .unwrap_err();
    assert!(error.to_string().contains("passkey assertion rejected"));
}

#[test]
fn browser_context_requires_usable_identity_and_exact_secure_origin() {
    let f = fixture();
    let base = context(f.oracle.public_root());
    let configured = wallet_call(&base, "configure", json!({})).unwrap();
    assert_eq!(configured["xpub"], f.oracle.public_root().to_string());
    assert_eq!(configured["origin"], ORIGIN);
    let mut wrong_network = base.clone();
    wrong_network.identity.xpub.network = bitcoin::NetworkKind::Main;
    let mut no_opt_in = base.clone();
    no_opt_in.allow_local_dev = false;
    let mut wrong_rp = base.clone();
    wrong_rp.rp_id = "attacker.example".into();
    let mut origin_path = base.clone();
    origin_path.origin.push_str("/wallet");
    let mut insecure = base.clone();
    insecure.rp_id = "wallet.example".into();
    insecure.origin = "http://wallet.example".into();
    let mut unusable_depth = base.clone();
    unusable_depth.identity.xpub.depth = 246;
    let mut missing_v2 = base.clone();
    missing_v2
        .identity
        .signing
        .inline_evaluators
        .retain(|entry| entry.wasm_version != 2);
    for context in [
        wrong_network,
        no_opt_in,
        wrong_rp,
        origin_path,
        insecure,
        unusable_depth,
        missing_v2,
    ] {
        assert!(wallet_call(&context, "configure", json!({})).is_err());
    }
}
