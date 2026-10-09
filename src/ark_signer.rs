//! In-enclave program evaluation and one-use nested MuSig sessions.
//!
//! The user nonce is fixed before the enclave reveals its nonce. Finishing removes
//! the secret nonce before validating any remaining peer data. Sessions are never
//! serialized, restored, or retried; a lost response requires a fresh session.
//! The service never receives the user's partial signature, so it cannot complete
//! a transaction before the wallet's durable-recovery barrier.

use anyhow::{anyhow, bail, ensure, Context, Result};
use ark::musig::nested::{Intent, MemberNonce, Nonce, Session};
use ark::sapio::protocol::{
    parse_nonce, parse_partial, CancelRequest, FinishRequest, FinishResponse, PrepareRequest,
    PrepareResponse, SigningAction, SIGNING_PROTOCOL,
};
use bitcoin::bip32::{Xpriv, Xpub};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{rand::RngCore, Scalar};
use emulator_connect::program::{ProgramError, WasmEvaluator};
use sapio_base::program::{
    program_derivation_path, EvaluatorId, ProgramId, ProgramInstance, MAX_PROGRAM_ROOT_DEPTH,
};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const MAX_PENDING_SESSIONS: usize = 256;
pub const SESSION_LIFETIME_SECS: u64 = 120;

struct Pending {
    program_id: ProgramId,
    intent: Intent,
    user_nonce: MemberNonce,
    nonce: Nonce,
    expires: Instant,
}

pub struct ArkSigner {
    root: Xpriv,
    public_root: Xpub,
    evaluators: Vec<WasmEvaluator>,
    pending: Mutex<HashMap<sha256::Hash, Pending>>,
}

impl ArkSigner {
    pub fn new(root: Xpriv) -> Result<Self> {
        if root.depth > MAX_PROGRAM_ROOT_DEPTH {
            return Err(ProgramError::RootDepth(root.depth).into());
        }
        Ok(Self {
            public_root: Xpub::from_priv(&ark::SECP, &root),
            root,
            evaluators: crate::deployment::evaluators()?,
            pending: Mutex::new(HashMap::new()),
        })
    }

    pub fn prepare(&self, request: PrepareRequest) -> Result<PrepareResponse> {
        ensure!(request.protocol == SIGNING_PROTOCOL, "unsupported signing protocol");
        ensure!(request.key.root == self.public_root, "wrong attested program root");
        let intent = request.action.intent(&request.key)?;
        let user_nonce = MemberNonce::from_bytes(
            intent,
            request.key.user_pubkey,
            parse_nonce(&request.user_nonce)?.serialize(),
        )?;
        let program = ProgramInstance::new(
            EvaluatorId(request.key.program.evaluator()),
            request.key.program.program().to_vec(),
            request.key.program.parameters().to_vec(),
        )?;
        ensure!(program.id().0 == request.key.program.id(), "program identity encoding mismatch");
        ensure!(
            program.derive_public_key(&request.key.root)?.public_key(bitcoin::secp256k1::Parity::Even)
                == intent.members[1],
            "program public-key derivation mismatch"
        );

        match &request.action {
            SigningAction::Spend { request: spend } => {
                let input = spend.signing_input(&request.key)?;
                crate::evaluator::authorize(
                    &self.evaluators, &program, &input, &spend.witness, &intent.message,
                )?;
            }
            SigningAction::Ownership { request: ownership } => {
                // These fixed native domains are not Bitcoin signature hashes.
                // Their complete request is bound by the native message function;
                // only a later, separately evaluated spend can transfer coins.
                ensure!(
                    ownership.message(&request.key)?.as_ref() == &intent.message,
                    "ownership request differs from the nested signing intent"
                );
            }
        }

        let now = Instant::now();
        let mut pending = self.pending.lock().map_err(|_| anyhow!("signer state unavailable"))?;
        pending.retain(|_, session| session.expires > now);
        ensure!(pending.len() < MAX_PENDING_SESSIONS, "signer session capacity exceeded");
        let nonce = Nonce::new(intent, intent.members[1])?;
        let program_nonce = hex::encode(nonce.public().serialize());
        let mut bytes = [0u8; 32];
        let session = loop {
            bitcoin::secp256k1::rand::rngs::OsRng.fill_bytes(&mut bytes);
            let id = sha256::Hash::from_byte_array(bytes);
            if !pending.contains_key(&id) { break id; }
        };
        pending.insert(session, Pending {
            program_id: program.id(),
            intent,
            user_nonce,
            nonce,
            expires: now + Duration::from_secs(SESSION_LIFETIME_SECS),
        });
        Ok(PrepareResponse { protocol: SIGNING_PROTOCOL.into(), session, program_nonce })
    }

    pub fn finish(&self, request: FinishRequest) -> Result<FinishResponse> {
        // Remove before every other check, including malformed public data. A
        // concurrent/replayed request cannot observe or reuse this secret nonce.
        let pending = self.pending.lock().map_err(|_| anyhow!("signer state unavailable"))?
            .remove(&request.session).context("unknown, expired or consumed signing session")?;
        ensure!(request.protocol == SIGNING_PROTOCOL, "unsupported signing protocol");
        ensure!(pending.expires > Instant::now(), "signing session expired");
        let server_nonce = request.server_nonce.as_deref().map(parse_nonce).transpose()?;
        let server_partial = request.server_partial.as_deref().map(parse_partial).transpose()?;
        if pending.intent.server.is_none() && server_partial.is_some() {
            bail!("server share supplied for a joint-key-only signature");
        }
        let session = Session::new(
            pending.intent,
            [pending.user_nonce, pending.nonce.public()],
            server_nonce,
        )?;
        if let Some(partial) = server_partial.as_ref() {
            session.verify_server(partial)?;
        }
        // The original Sapio scheme is x-only. Normalize its private key too:
        // adding zero as an x-only tweak makes its full public point even.
        let mut derived = self.root.derive_priv(&ark::SECP, &program_derivation_path(pending.program_id))?;
        let keypair = derived.to_keypair(&ark::SECP);
        derived.private_key.non_secure_erase();
        let mut keypair = keypair.add_xonly_tweak(&ark::SECP, &Scalar::ZERO)?;
        let result = pending.nonce.sign(&keypair, &session);
        keypair.non_secure_erase();
        let partial = result?;
        Ok(FinishResponse {
            protocol: SIGNING_PROTOCOL.into(),
            program_partial: hex::encode(partial.serialize()),
        })
    }

    pub fn cancel(&self, request: CancelRequest) -> Result<()> {
        let removed = self.pending.lock().map_err(|_| anyhow!("signer state unavailable"))?
            .remove(&request.session);
        ensure!(request.protocol == SIGNING_PROTOCOL, "unsupported signing protocol");
        ensure!(removed.is_some(), "unknown, expired or consumed signing session");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::{PAY_AT_LEAST_SELECTOR, PAY_AT_LEAST_WASM};
    use ark::musig::{self, context::SigningInput, PartialSignature};
    use ark::sapio::program::{Program, ProgramKey};
    use ark::sapio::protocol::SpendRequest;
    use ark::vtxo::{policy::check_block_delta, PubkeyVtxoPolicy, TapScriptClause};
    use bitcoin::bip32::Xpub;
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::HashEngine;
    use bitcoin::secp256k1::{schnorr, Keypair, Message, PublicKey, SecretKey};
    use bitcoin::sighash::{Prevouts, SighashCache};
    use bitcoin::taproot::{LeafVersion, TapLeafHash};
    use bitcoin::{
        absolute, transaction, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction,
        TapSighashType, TxIn, TxOut, Txid,
    };
    use std::sync::Barrier;
    use std::thread;

    // These are the existing source-built predicates, not approval callbacks.
    // Their source, ABI and binary provenance live beside the example artifacts.
    const TEMPLATEHASH: &[u8] = include_bytes!("../examples/templatehash/templatehash.wasm");
    const VAULT: &[u8] = include_bytes!("../examples/vault/vault.wasm");
    const FUNDING: u64 = 10_000;
    const EXIT_DELAY: u16 = 12;

    // Public deterministic keys are ONLY synthetic test fixtures. Signer sessions
    // and both nested secret nonces still use the production CSPRNG. Assertions
    // never depend on their bytes, wall-clock scheduling, a node or a service.
    fn root() -> Xpriv {
        Xpriv::new_master(Network::Regtest, &[0x41; 32]).unwrap()
    }

    fn key(byte: u8) -> Keypair {
        Keypair::from_secret_key(&ark::SECP, &SecretKey::from_slice(&[byte; 32]).unwrap())
    }

    fn signer() -> ArkSigner {
        ArkSigner::new(root()).unwrap()
    }

    fn recipient(byte: u8) -> ScriptBuf {
        ScriptBuf::new_p2tr(&ark::SECP, key(byte).x_only_public_key().0, None)
    }

    fn transaction() -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::from_consensus(500),
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([0x44; 32]), 0),
                sequence: Sequence::from_height(EXIT_DELAY),
                ..TxIn::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: recipient(0x45),
            }],
        }
    }

    fn template_hash(tx: &Transaction, input_index: u32) -> [u8; 32] {
        let mut sequences = sha256::Hash::engine();
        for input in &tx.input {
            sequences.input(&input.sequence.to_consensus_u32().to_le_bytes());
        }
        let mut outputs = sha256::Hash::engine();
        for output in &tx.output {
            outputs.input(&serialize(output));
        }
        let tag = sha256::Hash::hash(b"TemplateHash");
        let mut hash = sha256::Hash::engine();
        hash.input(tag.as_byte_array());
        hash.input(tag.as_byte_array());
        hash.input(&tx.version.0.to_le_bytes());
        hash.input(&tx.lock_time.to_consensus_u32().to_le_bytes());
        hash.input(sha256::Hash::from_engine(sequences).as_byte_array());
        hash.input(sha256::Hash::from_engine(outputs).as_byte_array());
        hash.input(&[0]); // BIP-446 annex-absent v1 view.
        hash.input(&input_index.to_le_bytes());
        sha256::Hash::from_engine(hash).to_byte_array()
    }

    fn template_program(tx: &Transaction) -> Program {
        Program::new(
            EvaluatorId::wasm().0, TEMPLATEHASH.to_vec(), template_hash(tx, 0).to_vec(),
        ).unwrap()
    }

    fn payment_parameters(amount: u64) -> Vec<u8> {
        let destination = recipient(0x45);
        let mut parameters = amount.to_le_bytes().to_vec();
        parameters.extend_from_slice(&(destination.len() as u32).to_le_bytes());
        parameters.extend_from_slice(destination.as_bytes());
        parameters
    }

    fn payment_program() -> Program {
        Program::new(
            EvaluatorId::for_wasm(PAY_AT_LEAST_WASM).0,
            PAY_AT_LEAST_SELECTOR.to_vec(),
            payment_parameters(9_000),
        ).unwrap()
    }

    #[derive(Clone)]
    struct Fixture {
        key: ProgramKey,
        input: SigningInput,
        server: Option<Keypair>,
        witness: Vec<u8>,
    }

    impl Fixture {
        fn new(program: Program, mut tx: Transaction, claim: bool) -> Self {
            let server = key(0x43);
            let key = ProgramKey {
                program,
                root: Xpub::from_priv(&ark::SECP, &root()),
                user_pubkey: key(0x42).public_key(),
            };
            let group = key.public_key().unwrap();
            let policy = PubkeyVtxoPolicy { user_pubkey: group };
            let delta = check_block_delta(EXIT_DELAY).unwrap();
            let tree = policy.taproot(server.public_key(), delta);
            let funding_output = TxOut {
                value: Amount::from_sat(FUNDING),
                script_pubkey: ScriptBuf::new_p2tr_tweaked(tree.output_key()),
            };
            let funding = Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![TxIn::default()],
                output: vec![funding_output.clone()],
            };
            tx.input[0].previous_output = OutPoint::new(funding.compute_txid(), 0);
            let mut prevouts = vec![funding_output];
            prevouts.extend((1..tx.input.len()).map(|_| TxOut {
                value: Amount::from_sat(5_000),
                script_pubkey: recipient(0x46),
            }));
            let mut input = SigningInput::key_spend(
                tx, 0, prevouts, &tree, vec![group, server.public_key()],
            ).unwrap();
            input.psbt.inputs[0].non_witness_utxo = Some(funding);
            if claim {
                let script = policy.user_pubkey_claim_clause(delta).tapscript();
                input.script_leaf = Some(TapLeafHash::from_script(&script, LeafVersion::TapScript));
                input.participants = vec![key.user_pubkey, key.program_pubkey().unwrap()];
                input.tweak = None;
            }
            input.sighash().unwrap();
            Self { key, input, server: (!claim).then_some(server), witness: vec![] }
        }

        fn template(claim: bool) -> Self {
            let tx = transaction();
            Self::new(template_program(&tx), tx, claim)
        }

        fn action(&self) -> SigningAction {
            SigningAction::Spend {
                request: SpendRequest::from_input(
                    &self.input, self.server.as_ref().map(Keypair::public_key), self.witness.clone(),
                ).unwrap(),
            }
        }

        fn request(&self) -> (PrepareRequest, Nonce) {
            let action = self.action();
            let intent = action.intent(&self.key).unwrap();
            let nonce = Nonce::new(intent, self.key.user_pubkey).unwrap();
            (PrepareRequest {
                protocol: SIGNING_PROTOCOL.into(),
                key: self.key.clone(),
                action,
                user_nonce: hex::encode(nonce.public().serialize()),
            }, nonce)
        }

        fn prepare(&self, signer: &ArkSigner) -> Prepared {
            let (request, user_nonce) = self.request();
            let intent = request.action.intent(&request.key).unwrap();
            let response = signer.prepare(request).unwrap();
            assert_eq!(response.protocol, SIGNING_PROTOCOL);
            let program_nonce = MemberNonce::from_bytes(
                intent, self.key.program_pubkey().unwrap(),
                parse_nonce(&response.program_nonce).unwrap().serialize(),
            ).unwrap();
            let (server_secret, server_public) = match &self.server {
                Some(key) => {
                    let (secret, public) = musig::nonce_pair_with_msg(key, &intent.message);
                    (Some(secret), Some(public))
                }
                None => (None, None),
            };
            let session = Session::new(
                intent, [user_nonce.public(), program_nonce], server_public,
            ).unwrap();
            // This is the ordinary Ark server signing API, independently
            // reconstructing the native sorted outer KeyAgg(C,A) and its tweak.
            let server_partial = server_secret.map(|secret| {
                let (partial, _) = musig::partial_sign(
                    self.input.participants.iter().copied(), session.aggregate_nonce(),
                    self.server.as_ref().unwrap(), secret, intent.message, intent.tweak, None,
                );
                session.verify_server(&partial).unwrap();
                partial
            });
            let finish = FinishRequest {
                protocol: SIGNING_PROTOCOL.into(),
                session: response.session,
                server_nonce: server_public.map(|nonce| hex::encode(nonce.serialize())),
                server_partial: server_partial.as_ref().map(|share| hex::encode(share.serialize())),
            };
            Prepared { user_nonce, session, server_partial, finish }
        }

        fn sign(&self, signer: &ArkSigner) -> schnorr::Signature {
            let prepared = self.prepare(signer);
            let response = signer.finish(prepared.finish.clone()).unwrap();
            assert!(signer.finish(prepared.finish.clone()).is_err());
            prepared.complete(self, response)
        }

        fn verify(&self, signature: &schnorr::Signature) {
            self.input.verify_signature(signature).unwrap();
            let prevouts: Vec<_> = self.input.psbt.inputs.iter()
                .map(|input| input.witness_utxo.as_ref().unwrap()).collect();
            let mut cache = SighashCache::new(&self.input.psbt.unsigned_tx);
            let hash = match self.input.script_leaf {
                Some(leaf) => cache.taproot_script_spend_signature_hash(
                    self.input.input_index, &Prevouts::All(&prevouts), leaf, TapSighashType::Default,
                ).unwrap(),
                None => cache.taproot_key_spend_signature_hash(
                    self.input.input_index, &Prevouts::All(&prevouts), TapSighashType::Default,
                ).unwrap(),
            };
            let verification_key = if self.input.script_leaf.is_some() {
                self.key.public_key().unwrap().x_only_public_key().0
            } else {
                bitcoin::secp256k1::XOnlyPublicKey::from_slice(
                    &prevouts[self.input.input_index].script_pubkey.as_bytes()[2..],
                ).unwrap()
            };
            ark::SECP.verify_schnorr(
                signature, &Message::from_digest(hash.to_byte_array()), &verification_key,
            ).unwrap();
            assert_eq!(hash.to_byte_array(), self.input.sighash().unwrap());
        }
    }

    struct Prepared {
        user_nonce: Nonce,
        session: Session,
        server_partial: Option<PartialSignature>,
        finish: FinishRequest,
    }

    impl Prepared {
        fn complete(self, fixture: &Fixture, response: FinishResponse) -> schnorr::Signature {
            assert_eq!(response.protocol, SIGNING_PROTOCOL);
            let program_partial = parse_partial(&response.program_partial).unwrap();
            self.session.verify_member(1, &program_partial).unwrap();
            // U signs last, locally. Neither U's secret nor its share is ever
            // a field in a request to ArkSigner.
            let user_partial = self.user_nonce.sign(&key(0x42), &self.session).unwrap();
            let members = [user_partial, program_partial];
            let signature = self.session.aggregate(&members, self.server_partial.as_ref()).unwrap();
            if let Some(server) = &self.server_partial {
                let group = self.session.combine_members(&members).unwrap();
                let native = musig::combine_partial_signatures(
                    fixture.input.participants.iter().copied(), self.session.aggregate_nonce(),
                    self.session.intent().message, self.session.intent().tweak, &[&group, server],
                );
                assert_eq!(native, signature);
            }
            fixture.verify(&signature);
            signature
        }
    }

    fn refused(signer: &ArkSigner, request: PrepareRequest) -> anyhow::Error {
        let before = signer.pending.lock().unwrap().len();
        let error = signer.prepare(request).expect_err("unauthorized request exposed a program nonce");
        assert_eq!(signer.pending.lock().unwrap().len(), before);
        error
    }

    fn predicate_refused(signer: &ArkSigner, fixture: &Fixture) {
        let (request, _) = fixture.request();
        let error = refused(signer, request);
        assert!(matches!(error.downcast_ref::<ProgramError>(), Some(ProgramError::Rejected)),
            "expected actual WASM policy refusal, got {error:#}");
    }

    fn invalid_evaluation(signer: &ArkSigner, fixture: &Fixture) {
        let (request, _) = fixture.request();
        let error = refused(signer, request);
        assert!(matches!(error.downcast_ref::<ProgramError>(), Some(ProgramError::Evaluation(_))),
            "expected actual WASM evaluation failure, got {error:#}");
    }

    #[test]
    fn templatehash_authorizes_native_outer_and_server_free_delayed_claim() {
        let signer = signer();
        for claim in [false, true] {
            let fixture = Fixture::template(claim);
            let signature = fixture.sign(&signer);
            if claim {
                let policy = PubkeyVtxoPolicy { user_pubkey: fixture.key.public_key().unwrap() };
                let clause = policy.user_pubkey_claim_clause(check_block_delta(EXIT_DELAY).unwrap());
                let (control, _) = fixture.input.psbt.inputs[0].tap_scripts.iter().next().unwrap();
                let witness = clause.witness(&signature, control);
                assert_eq!(witness.len(), 3);
                assert_eq!(witness.iter().next().unwrap(), &signature[..]);
                assert_eq!(fixture.input.psbt.unsigned_tx.input[0].sequence, clause.sequence());
            }
            let mut changed = fixture.input.clone();
            changed.psbt.unsigned_tx.output[0].value += Amount::ONE_SAT;
            assert!(changed.verify_signature(&signature).is_err());
        }
        assert!(signer.pending.lock().unwrap().is_empty());
    }

    #[test]
    fn templatehash_rejects_every_committed_transaction_field_before_nonce() {
        let signer = signer();
        let mut tx = transaction();
        tx.input.push(TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([0x47; 32]), 1),
            sequence: Sequence(22),
            ..TxIn::default()
        });
        tx.output.push(TxOut { value: Amount::from_sat(500), script_pubkey: recipient(0x48) });
        let original = Fixture::new(template_program(&tx), tx, false);
        original.sign(&signer);
        let mutations: [fn(&mut Transaction); 6] = [
            |tx| tx.output[0].script_pubkey = recipient(0x49),
            |tx| tx.output[1].value += Amount::ONE_SAT,
            |tx| tx.input[0].sequence = Sequence(13),
            |tx| tx.input[1].sequence = Sequence(23),
            |tx| tx.lock_time = absolute::LockTime::from_consensus(501),
            |tx| tx.version = transaction::Version::ONE,
        ];
        for mutate in mutations {
            let mut changed = original.clone();
            mutate(&mut changed.input.psbt.unsigned_tx);
            predicate_refused(&signer, &changed);
        }
        // Authenticate the same program at a different input. Only its selected
        // index changes in the template commitment; both prevouts remain real
        // funding proofs, so rejection must come from the WASM predicate.
        let mut other_index = original.clone();
        let mut second_funding = original.input.psbt.inputs[0].non_witness_utxo.clone().unwrap();
        second_funding.input[0].previous_output.vout = 1;
        other_index.input.psbt.inputs[1] = original.input.psbt.inputs[0].clone();
        other_index.input.psbt.unsigned_tx.input[1].previous_output =
            OutPoint::new(second_funding.compute_txid(), 0);
        other_index.input.psbt.inputs[1].non_witness_utxo = Some(second_funding);
        other_index.input.input_index = 1;
        predicate_refused(&signer, &other_index);
        let mut wrong_commitment = template_hash(&original.input.psbt.unsigned_tx, 0);
        wrong_commitment[0] ^= 1;
        let wrong_program = Program::new(
            EvaluatorId::wasm().0, TEMPLATEHASH.to_vec(), wrong_commitment.to_vec(),
        ).unwrap();
        let wrong = Fixture::new(wrong_program, original.input.psbt.unsigned_tx.clone(), false);
        predicate_refused(&signer, &wrong);
    }

    #[test]
    fn templatehash_free_prevouts_do_not_free_the_bitcoin_signature() {
        let signer = signer();
        let original = Fixture::template(false);
        let signature = original.sign(&signer);
        // TemplateHash deliberately omits prevouts and amounts. Rebind the
        // complete funding proof, not just attacker-controlled PSBT metadata.
        let mut rebound = original.clone();
        let parent = rebound.input.psbt.inputs[0].non_witness_utxo.as_mut().unwrap();
        parent.output[0].value += Amount::from_sat(1_000);
        let prevout = parent.output[0].clone();
        let point = OutPoint::new(parent.compute_txid(), 0);
        rebound.input.psbt.inputs[0].witness_utxo = Some(prevout);
        rebound.input.psbt.unsigned_tx.input[0].previous_output = point;
        assert_eq!(template_hash(&original.input.psbt.unsigned_tx, 0),
            template_hash(&rebound.input.psbt.unsigned_tx, 0));
        assert_ne!(original.input.sighash().unwrap(), rebound.input.sighash().unwrap());
        assert!(rebound.input.verify_signature(&signature).is_err());
        let rebound_signature = rebound.sign(&signer);
        assert!(original.input.verify_signature(&rebound_signature).is_err());

        let mutations: [fn(&mut SigningInput); 4] = [
            |input| input.psbt.unsigned_tx.input[0].previous_output.vout = 1,
            |input| input.psbt.unsigned_tx.input[0].previous_output.txid = Txid::from_byte_array([9; 32]),
            |input| input.psbt.inputs[0].witness_utxo.as_mut().unwrap().value += Amount::ONE_SAT,
            |input| input.psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey = recipient(0x49),
        ];
        for mutate in mutations {
            let (mut request, _) = original.request();
            let mut unauthenticated = original.clone();
            mutate(&mut unauthenticated.input);
            request.action = unauthenticated.action();
            refused(&signer, request);
        }
    }

    #[test]
    fn generic_sweep_enforces_fee_and_single_complete_destination() {
        let signer = signer();
        let program = Program::new(
            EvaluatorId::wasm().0, VAULT.to_vec(), payment_parameters(1_000),
        ).unwrap();
        let original = Fixture::new(program, transaction(), true);
        original.sign(&signer);
        let mut lower_fee = original.clone();
        lower_fee.input.psbt.unsigned_tx.output[0].value = Amount::from_sat(FUNDING);
        lower_fee.sign(&signer);
        let mutations: [fn(&mut Transaction); 4] = [
            |tx| tx.output[0].value = Amount::from_sat(8_999),
            |tx| tx.output[0].value = Amount::from_sat(FUNDING + 1),
            |tx| tx.output[0].script_pubkey = recipient(0x49),
            |tx| tx.output.push(TxOut { value: Amount::from_sat(330), script_pubkey: recipient(0x49) }),
        ];
        for mutate in mutations {
            let mut changed = original.clone();
            mutate(&mut changed.input.psbt.unsigned_tx);
            // Keep PSBT output maps structurally consistent so this really
            // reaches the generic evaluator, rather than a PSBT parser error.
            changed.input.psbt.outputs.resize_with(
                changed.input.psbt.unsigned_tx.output.len(), Default::default,
            );
            predicate_refused(&signer, &changed);
        }
    }

    #[test]
    fn registered_payment_evidence_selects_the_actual_output() {
        let signer = signer();
        let mut tx = transaction();
        tx.output.push(TxOut { value: Amount::from_sat(500), script_pubkey: recipient(0x48) });
        let mut original = Fixture::new(payment_program(), tx, false);
        original.witness = 0u32.to_le_bytes().to_vec();
        original.sign(&signer);
        let mut reordered = original.clone();
        reordered.input.psbt.unsigned_tx.output[0].value += Amount::ONE_SAT;
        reordered.input.psbt.unsigned_tx.output.swap(0, 1);
        reordered.witness = 1u32.to_le_bytes().to_vec();
        assert_eq!(original.key, reordered.key);
        assert_eq!(original.input.psbt.inputs, reordered.input.psbt.inputs);
        reordered.sign(&signer);

        for evidence in [1u32, 2, u32::MAX] {
            let mut wrong = original.clone();
            wrong.witness = evidence.to_le_bytes().to_vec();
            predicate_refused(&signer, &wrong);
        }
        for witness in [vec![], vec![0; 3], vec![0; 5]] {
            let mut wrong = original.clone();
            wrong.witness = witness;
            invalid_evaluation(&signer, &wrong);
        }
        let mut underpaid = original.clone();
        underpaid.input.psbt.unsigned_tx.output[0].value -= Amount::ONE_SAT;
        predicate_refused(&signer, &underpaid);
        let mut redirected = original.clone();
        redirected.input.psbt.unsigned_tx.output[0].script_pubkey = recipient(0x49);
        predicate_refused(&signer, &redirected);
        // Rejection neither poisons the evaluator nor prevents a fresh session.
        original.sign(&signer);
    }

    #[test]
    fn mismatched_identity_parameters_roots_and_claim_proofs_never_expose_nonce() {
        let signer = signer();
        let original = Fixture::template(true);
        let program = &original.key.program;
        let alternatives = [
            payment_program(),
            Program::new(program.evaluator(), program.program().to_vec(), vec![0; 32]).unwrap(),
            Program::new(EvaluatorId::wasm_v2().0, program.program().to_vec(),
                program.parameters().to_vec()).unwrap(),
        ];
        for alternative in alternatives {
            let (mut request, _) = original.request();
            request.key.program = alternative;
            assert_ne!(request.key.program.id(), original.key.program.id());
            assert_ne!(request.key.program_pubkey().unwrap(), original.key.program_pubkey().unwrap());
            refused(&signer, request);
        }
        let other_root = Xpriv::new_master(Network::Regtest, &[0x51; 32]).unwrap();
        let (mut request, _) = original.request();
        request.key.root = Xpub::from_priv(&ark::SECP, &other_root);
        refused(&signer, request);
        let mut deep_root = root();
        deep_root.depth = MAX_PROGRAM_ROOT_DEPTH + 1;
        assert!(ArkSigner::new(deep_root).is_err());

        let mutations: [fn(&mut SigningInput); 4] = [
            |input| input.psbt.inputs[0].tap_scripts.clear(),
            |input| input.psbt.inputs[0].tap_internal_key = Some(key(0x52).x_only_public_key().0),
            |input| input.psbt.inputs[0].tap_merkle_root = None,
            |input| input.script_leaf = Some(TapLeafHash::from_byte_array([0x53; 32])),
        ];
        for mutate in mutations {
            let (mut request, _) = original.request();
            let mut wrong = original.clone();
            mutate(&mut wrong.input);
            request.action = wrong.action();
            refused(&signer, request);
        }
    }

    #[test]
    fn unavailable_and_unsupported_evaluators_fail_before_nonce() {
        let mut unavailable = signer();
        unavailable.evaluators.clear();
        let mut payment = Fixture::new(payment_program(), transaction(), false);
        payment.witness = 0u32.to_le_bytes().to_vec();
        let error = refused(&unavailable, payment.request().0);
        assert!(matches!(error.downcast_ref::<ProgramError>(), Some(ProgramError::UnknownEvaluator(_))));

        let signer = signer();
        let unknown = Program::new(
            sha256::Hash::hash(b"uninstalled evaluator"), b"program".to_vec(), vec![],
        ).unwrap();
        let fixture = Fixture::new(unknown, transaction(), false);
        let error = refused(&signer, fixture.request().0);
        assert!(matches!(error.downcast_ref::<ProgramError>(), Some(ProgramError::UnknownEvaluator(_))));
        // Real v1 guest bytes are not a v2 implementation: missing v2 exports
        // must fail, not silently fall back to another ABI.
        let unsupported = Program::new(
            EvaluatorId::wasm_v2().0, TEMPLATEHASH.to_vec(), template_hash(&transaction(), 0).to_vec(),
        ).unwrap();
        invalid_evaluation(&signer, &Fixture::new(unsupported, transaction(), false));
        Fixture::template(false).sign(&signer);
    }

    #[test]
    fn unrelated_recovery_and_checkpoint_transactions_have_no_privileged_permit() {
        let signer = signer();
        let original = Fixture::template(true);
        original.sign(&signer);
        // Exact TemplateHash is not a complete Ark policy: it cannot authorize
        // unrelated checkpoint/recovery shapes. Even this authenticated C claim
        // needs a fresh successful evaluation of its actual transaction.
        let mut recovery = original.clone();
        recovery.input.psbt.unsigned_tx.output[0].script_pubkey = recipient(0x42);
        predicate_refused(&signer, &recovery);
        recovery.witness = b"recovery".to_vec();
        invalid_evaluation(&signer, &recovery);
        let mut checkpoint = Fixture::template(false);
        checkpoint.input.psbt.unsigned_tx.output[0].script_pubkey =
            checkpoint.input.psbt.inputs[0].witness_utxo.as_ref().unwrap().script_pubkey.clone();
        predicate_refused(&signer, &checkpoint);

        let (request, _) = original.request();
        let mut raw = serde_json::to_value(&request).unwrap();
        raw["action"] = serde_json::json!({
            "type": "sign-digest", "message": original.input.sighash().unwrap(),
        });
        assert!(serde_json::from_value::<PrepareRequest>(raw).is_err());
        let mut privileged = serde_json::to_value(&request).unwrap();
        privileged["action"]["request"]["recovery"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PrepareRequest>(privileged).is_err());
        assert!(signer.pending.lock().unwrap().is_empty());
    }

    fn consumed(signer: &ArkSigner, prepared: &Prepared, invalid: FinishRequest) {
        assert!(signer.finish(invalid).is_err());
        assert!(!signer.pending.lock().unwrap().contains_key(&prepared.finish.session));
        assert!(signer.finish(prepared.finish.clone()).is_err());
    }

    #[test]
    fn malformed_finish_and_wrong_server_shares_consume_the_session() {
        let signer = signer();
        let fixture = Fixture::template(false);
        let mutations: [fn(&mut FinishRequest); 6] = [
            |request| request.protocol = "unsupported".into(),
            |request| request.server_nonce = Some("not-hex".into()),
            |request| request.server_nonce = Some(hex::encode([0; 66])),
            |request| request.server_nonce = None,
            |request| request.server_partial = Some("not-hex".into()),
            |request| request.server_partial = Some(hex::encode([0; 32])),
        ];
        for mutate in mutations {
            let prepared = fixture.prepare(&signer);
            let mut bad = prepared.finish.clone();
            mutate(&mut bad);
            consumed(&signer, &prepared, bad);
        }
        let first = fixture.prepare(&signer);
        let second = fixture.prepare(&signer);
        let mut crossed = first.finish.clone();
        crossed.server_partial = second.finish.server_partial.clone();
        consumed(&signer, &first, crossed);
        let response = signer.finish(second.finish.clone()).unwrap();
        second.complete(&fixture, response);

        let claim = Fixture::template(true);
        let prepared = claim.prepare(&signer);
        let mut extraneous = prepared.finish.clone();
        extraneous.server_partial = Some(hex::encode([0; 32]));
        consumed(&signer, &prepared, extraneous);
    }

    #[test]
    fn cancelling_aggregate_nonce_consumes_the_session() {
        let signer = signer();
        let fixture = Fixture::template(false);
        let prepared = fixture.prepare(&signer);
        let mut inverse = prepared.session.group_nonce().serialize();
        for point in inverse.chunks_exact_mut(33) {
            let negative = PublicKey::from_slice(point).unwrap().negate(&ark::SECP);
            point.copy_from_slice(&negative.serialize());
        }
        let inverse = musig::PublicNonce::from_byte_array(&inverse).unwrap();
        let mut cancel = prepared.finish.clone();
        cancel.server_nonce = Some(hex::encode(inverse.serialize()));
        cancel.server_partial = None;
        consumed(&signer, &prepared, cancel);
    }

    #[test]
    fn cancellation_and_expiry_are_terminal_without_sleeping() {
        let signer = signer();
        let fixture = Fixture::template(true);
        for protocol in [SIGNING_PROTOCOL, "unsupported"] {
            let prepared = fixture.prepare(&signer);
            let request = CancelRequest { protocol: protocol.into(), session: prepared.finish.session };
            assert_eq!(signer.cancel(request.clone()).is_ok(), protocol == SIGNING_PROTOCOL);
            assert!(signer.cancel(request).is_err());
            assert!(signer.finish(prepared.finish).is_err());
        }
        let expired = fixture.prepare(&signer);
        signer.pending.lock().unwrap().get_mut(&expired.finish.session).unwrap().expires =
            Instant::now() - Duration::from_secs(1);
        consumed(&signer, &expired, expired.finish.clone());
        let pruned = fixture.prepare(&signer);
        signer.pending.lock().unwrap().get_mut(&pruned.finish.session).unwrap().expires =
            Instant::now() - Duration::from_secs(1);
        let fresh = fixture.prepare(&signer);
        assert!(!signer.pending.lock().unwrap().contains_key(&pruned.finish.session));
        assert!(signer.finish(pruned.finish).is_err());
        let response = signer.finish(fresh.finish.clone()).unwrap();
        fresh.complete(&fixture, response);
    }

    #[test]
    fn concurrent_finish_releases_exactly_one_valid_share() {
        let signer = signer();
        let fixture = Fixture::template(false);
        let prepared = fixture.prepare(&signer);
        let barrier = Barrier::new(8);
        let results = thread::scope(|scope| {
            let handles: Vec<_> = (0..8).map(|_| {
                let request = prepared.finish.clone();
                let signer = &signer;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    signer.finish(request)
                })
            }).collect();
            handles.into_iter().map(|handle| handle.join().unwrap()).collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 7);
        assert!(signer.pending.lock().unwrap().is_empty());
        assert!(signer.finish(prepared.finish.clone()).is_err());
        prepared.complete(&fixture, results.into_iter().find_map(Result::ok).unwrap());
    }

    #[test]
    fn fresh_signer_with_identical_root_cannot_revive_old_sessions() {
        let fixture = Fixture::template(false);
        let first = signer();
        let old = fixture.prepare(&first);
        let old_root = first.public_root;
        drop(first);
        let restarted = signer();
        assert_eq!(restarted.public_root, old_root);
        assert!(restarted.finish(old.finish.clone()).is_err());
        assert!(restarted.cancel(CancelRequest {
            protocol: SIGNING_PROTOCOL.into(), session: old.finish.session,
        }).is_err());
        let fresh = fixture.prepare(&restarted);
        assert_ne!(fresh.finish.session, old.finish.session);
        assert!(restarted.finish(old.finish).is_err());
        let response = restarted.finish(fresh.finish.clone()).unwrap();
        fresh.complete(&fixture, response);
    }

    #[test]
    fn native_forfeit_can_receive_server_share_after_program_share() {
        let signer = signer();
        let fixture = Fixture::template(false);
        let prepared = fixture.prepare(&signer);
        let mut deferred = prepared.finish.clone();
        deferred.server_partial = None;
        let response = signer.finish(deferred).unwrap();
        assert!(signer.finish(prepared.finish.clone()).is_err());
        prepared.complete(&fixture, response);
    }

    fn test_program(version: u8, allocator: &str, predicate: &str, extra: &str) -> Program {
        let module = wat::parse_str(format!(r#"(module
            {extra}
            (memory (export "memory") 1)
            (global $heap (mut i32) (i32.const 4096))
            (func (export "sapio_alloc_v{version}") (param $length i32) (result i32)
                {allocator})
            (func (export "sapio_evaluate_v{version}")
                (param $program i32) (param $program_len i32)
                (param $parameters i32) (param $parameters_len i32)
                (param $view i32) (param $view_len i32)
                (param $witness i32) (param $witness_len i32) (result i32)
                {predicate}))"#)).unwrap();
        Program::new(
            if version == 1 { EvaluatorId::wasm().0 } else { EvaluatorId::wasm_v2().0 },
            module, vec![7],
        ).unwrap()
    }

    const TEST_ALLOCATOR: &str =
        "global.get $heap global.get $heap local.get $length i32.add global.set $heap";

    #[test]
    fn inline_v2_observes_authenticated_internal_key_and_no_unsigned_annex() {
        // The guest compares the v2 authenticated internal key with evidence and
        // checks actual signed fields, not a host-side approval callback.
        let program = test_program(2, TEST_ALLOCATOR, r#"
            (local $index i32)
            local.get $program_len i32.eqz
            local.get $view i32.load i32.const 2 i32.eq i32.and
            local.get $view i32.load offset=4 i32.const 500 i32.eq i32.and
            local.get $view i32.load offset=8 i32.eqz i32.and
            local.get $view local.get $view_len i32.add i32.const 4 i32.sub i32.load
                i32.eqz i32.and
            local.get $witness_len i32.const 32 i32.eq i32.and
            if else i32.const 0 return end
            block $done
                loop $compare
                    local.get $index i32.const 32 i32.eq br_if $done
                    local.get $view local.get $view_len i32.add i32.const 36 i32.sub
                        local.get $index i32.add i32.load8_u
                    local.get $witness local.get $index i32.add i32.load8_u
                    i32.ne if i32.const 0 return end
                    local.get $index i32.const 1 i32.add local.set $index
                    br $compare
                end
            end
            i32.const 1
        "#, "");
        let signer = signer();
        for claim in [false, true] {
            let mut fixture = Fixture::new(program.clone(), transaction(), claim);
            fixture.witness = fixture.input.psbt.inputs[0].tap_internal_key.unwrap()
                .serialize().to_vec();
            fixture.sign(&signer);
            let mut wrong = fixture.clone();
            wrong.witness[0] ^= 1;
            predicate_refused(&signer, &wrong);
            let mut annex = fixture.clone();
            sapio_psbt::annex::set(&mut annex.input.psbt.inputs[0], Some(vec![0x50, 1])).unwrap();
            refused(&signer, annex.request().0);
            let mut finalized = fixture.clone();
            finalized.input.psbt.inputs[0].final_script_sig = Some(ScriptBuf::new());
            let error = refused(&signer, finalized.request().0);
            assert!(matches!(error.downcast_ref::<ProgramError>(), Some(ProgramError::FinalizedInput)));
            let mut all = fixture.clone();
            all.input.psbt.inputs[0].sighash_type = Some(TapSighashType::All.into());
            let (mut request, _) = fixture.request();
            request.action = all.action();
            refused(&signer, request);
        }
    }

    #[test]
    fn private_adapter_rejects_unsafe_guests_without_exposing_a_nonce() {
        let signer = signer();
        for (allocator, predicate, extra) in [
            ("i32.const 4096", "i32.const 1", ""),
            ("i32.const -1", "i32.const 1", ""),
            (TEST_ALLOCATOR, "unreachable", ""),
            (TEST_ALLOCATOR, "i32.const 2", ""),
            (TEST_ALLOCATOR, "i32.const 1", "(func $start) (start $start)"),
            (TEST_ALLOCATOR, "i32.const 1",
                r#"(import "env" "approve" (func))"#),
        ] {
            let fixture = Fixture::new(
                test_program(1, allocator, predicate, extra), transaction(), false,
            );
            let error = refused(&signer, fixture.request().0);
            assert!(matches!(error.downcast_ref::<ProgramError>(), Some(ProgramError::Evaluation(_))));
        }
        // Every fill is in bounds, and the loop remains finite without metering.
        // Without the shared fuel limit these guests approve and expose a nonce.
        let burn = r#"
            (local $remaining i32)
            i32.const 2000 local.set $remaining
            loop $burn
                i32.const 0 i32.const 0 i32.const 65536 memory.fill
                local.get $remaining i32.const 1 i32.sub local.tee $remaining
                br_if $burn
            end
        "#;
        let allocating_burn = format!("{burn} {TEST_ALLOCATOR}");
        let evaluating_burn = format!("{burn} i32.const 1");
        for (allocator, predicate) in [
            (TEST_ALLOCATOR, evaluating_burn.as_str()),
            (allocating_burn.as_str(), "i32.const 1"),
        ] {
            let fixture = Fixture::new(
                test_program(1, allocator, predicate, ""), transaction(), false,
            );
            let error = refused(&signer, fixture.request().0);
            assert!(matches!(error.downcast_ref::<ProgramError>(), Some(ProgramError::Evaluation(_))));
        }
        Fixture::template(false).sign(&signer);
    }
}
