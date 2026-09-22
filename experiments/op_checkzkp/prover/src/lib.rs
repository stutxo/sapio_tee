//! Experimental in-memory Groth16 fixture, not production custody code.
//! Each instance performs a fresh local trusted setup using OS randomness;
//! this is not a production ceremony. No secret or proving key is written to disk.

use anyhow::{ensure, Context, Result};
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_ec::AffineRepr;
use ark_ff::{BigInt, PrimeField};
use ark_groth16::{
    prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey,
};
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, prelude::ToBitsGadget,
    uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

pub mod fixtures;

const DOMAIN: &[u8] = b"sapio/checkzkp/bn254/v1";
const VK_LEN: usize = 896;
const PARAMETERS_LEN: usize = 928;
const PROOF_LEN: usize = 256;
const WITNESS_LEN: usize = 288;

pub struct DemoProver {
    secret: [u8; 32],
    commitment: [u8; 32],
    proving_key: ProvingKey<Bn254>,
    verifying_key: PreparedVerifyingKey<Bn254>,
    parameters: Vec<u8>,
}

impl DemoProver {
    pub fn new() -> Result<Self> {
        let mut rng = OsRng;
        let mut secret = [0u8; 32];
        rng.try_fill_bytes(&mut secret)
            .context("obtaining private secret from OS randomness")?;
        let commitment: [u8; 32] = Sha256::digest(secret).into();
        let circuit = AuthorizationCircuit::new(secret, [0u8; 32]);
        // Toxic waste is freshly sampled inside arkworks, never seeded from a
        // published fixture. This local single-party setup is experimental only.
        let proving_key =
            Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng)
                .context("performing fresh local Groth16 setup")?;
        let mut parameters = encode_verifying_key(&proving_key.vk)?;
        parameters.extend_from_slice(&commitment);
        ensure!(parameters.len() == PARAMETERS_LEN, "invalid parameter size");

        // The native reference consumes the same coordinate encoding as WASM,
        // independently decoded and validated by arkworks rather than substrate-bn.
        let verifying_key = prepare_verifying_key(&decode_verifying_key(&parameters[..VK_LEN])?);
        Ok(Self {
            secret,
            commitment,
            proving_key,
            verifying_key,
            parameters,
        })
    }

    pub fn parameters(&self) -> Vec<u8> {
        self.parameters.clone()
    }

    pub fn prove(&self, encoded_view: &[u8]) -> Result<Vec<u8>> {
        let transaction = transaction_digest(encoded_view);
        let circuit = AuthorizationCircuit::new(self.secret, transaction);
        let authorization = circuit.authorization;
        let proof = Groth16::<Bn254>::create_random_proof_with_reduction(
            circuit,
            &self.proving_key,
            &mut OsRng,
        )
        .context("generating Groth16 authorization proof")?;
        let mut witness = Vec::with_capacity(WITNESS_LEN);
        encode_g1(&proof.a, &mut witness)?;
        encode_g2(&proof.b, &mut witness)?;
        encode_g1(&proof.c, &mut witness)?;
        witness.extend_from_slice(&authorization);
        ensure!(witness.len() == WITNESS_LEN, "invalid witness size");
        ensure!(
            self.verify(encoded_view, &witness)?,
            "freshly generated proof failed independent native verification"
        );
        Ok(witness)
    }

    // Malformed encodings return Err; well-formed but invalid proofs return false.
    // Verification uses only public data, never the stored secret or proving key.
    pub fn verify(&self, encoded_view: &[u8], witness: &[u8]) -> Result<bool> {
        ensure!(
            witness.len() == WITNESS_LEN,
            "witness must be exactly 288 bytes"
        );
        let proof = Proof::<Bn254> {
            a: decode_g1(&witness[..64]).context("decoding proof A")?,
            b: decode_g2(&witness[64..192]).context("decoding proof B")?,
            c: decode_g1(&witness[192..PROOF_LEN]).context("decoding proof C")?,
        };
        let authorization: [u8; 32] = witness[PROOF_LEN..].try_into()?;
        let transaction = transaction_digest(encoded_view);
        let inputs = public_inputs(&self.commitment, &transaction, &authorization);
        Groth16::<Bn254>::verify_proof(&self.verifying_key, &proof, &inputs)
            .context("verifying Groth16 authorization proof")
    }
}

struct AuthorizationCircuit {
    secret: [u8; 32],
    commitment: [u8; 32],
    transaction: [u8; 32],
    authorization: [u8; 32],
}

impl AuthorizationCircuit {
    fn new(secret: [u8; 32], transaction: [u8; 32]) -> Self {
        let commitment = Sha256::digest(secret).into();
        let mut hash = Sha256::new();
        hash.update(secret);
        hash.update(transaction);
        let authorization = hash.finalize().into();
        Self {
            secret,
            commitment,
            transaction,
            authorization,
        }
    }
}

impl ConstraintSynthesizer<Fr> for AuthorizationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let inputs = public_inputs(&self.commitment, &self.transaction, &self.authorization);
        let secret = UInt8::<Fr>::new_witness_vec(cs.clone(), &self.secret)?;
        let transaction = UInt8::<Fr>::new_witness_vec(cs.clone(), &self.transaction)?;
        let commitment = Sha256Gadget::<Fr>::digest(&secret)?;
        let mut hash = Sha256Gadget::<Fr>::default();
        hash.update(&secret)?;
        hash.update(&transaction)?;
        let authorization = hash.finalize()?;

        // Exactly six public scalars, in C/T/A order. Each is equated to a
        // 128-bit Boolean packing. Reversing bytes (not bits within each byte)
        // converts the external big-endian integer to le_bits_to_fp's input.
        // Because 2^128 < Fr::MODULUS, these equalities cannot wrap modulo Fr.
        // In particular T is NOT merely a witness: both halves are public and
        // constrained to the same bytes used in SHA256(secret || T).
        for (digest_index, digest) in [
            commitment.0.as_slice(),
            transaction.as_slice(),
            authorization.0.as_slice(),
        ]
        .into_iter()
        .enumerate()
        {
            for (half_index, half) in digest.as_chunks::<16>().0.iter().enumerate() {
                let public = FpVar::<Fr>::new_input(cs.clone(), || {
                    Ok(inputs[2 * digest_index + half_index])
                })?;
                let mut bits = Vec::with_capacity(128);
                for byte in half.iter().rev() {
                    bits.extend(byte.to_bits_le()?);
                }
                Boolean::le_bits_to_fp(&bits)?.enforce_equal(&public)?;
            }
        }
        Ok(())
    }
}

fn transaction_digest(encoded_view: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(Sha256::digest(encoded_view));
    hash.finalize().into()
}

fn public_inputs(
    commitment: &[u8; 32],
    transaction: &[u8; 32],
    authorization: &[u8; 32],
) -> [Fr; 6] {
    let digests = [commitment, transaction, authorization];
    std::array::from_fn(|index| {
        let start = (index % 2) * 16;
        let half: [u8; 16] = digests[index / 2][start..start + 16]
            .try_into()
            .expect("fixed 128-bit digest half");
        Fr::from(u128::from_be_bytes(half))
    })
}

fn encode_fq(value: &Fq, output: &mut Vec<u8>) {
    // Arkworks' internal integer has little-endian u64 limbs, not wire bytes.
    for limb in value.into_bigint().0.iter().rev() {
        output.extend_from_slice(&limb.to_be_bytes());
    }
}

fn encode_g1(point: &G1Affine, output: &mut Vec<u8>) -> Result<()> {
    ensure!(!point.is_zero(), "G1 infinity has no wire encoding");
    encode_fq(&point.x, output);
    encode_fq(&point.y, output);
    Ok(())
}

fn encode_g2(point: &G2Affine, output: &mut Vec<u8>) -> Result<()> {
    ensure!(!point.is_zero(), "G2 infinity has no wire encoding");
    encode_fq(&point.x.c0, output);
    encode_fq(&point.x.c1, output);
    encode_fq(&point.y.c0, output);
    encode_fq(&point.y.c1, output);
    Ok(())
}

fn decode_fq(bytes: &[u8]) -> Result<Fq> {
    ensure!(bytes.len() == 32, "Fq coordinate must be exactly 32 bytes");
    let mut limbs = [0u64; 4];
    for (limb, chunk) in limbs.iter_mut().rev().zip(bytes.as_chunks::<8>().0.iter()) {
        *limb = u64::from_be_bytes(*chunk);
    }
    // from_bigint rejects values >= q rather than reducing an invalid encoding.
    Fq::from_bigint(BigInt::<4>(limbs)).context("noncanonical Fq coordinate")
}

fn decode_g1(bytes: &[u8]) -> Result<G1Affine> {
    ensure!(bytes.len() == 64, "G1 point must be exactly 64 bytes");
    let point = G1Affine::new_unchecked(decode_fq(&bytes[..32])?, decode_fq(&bytes[32..])?);
    ensure!(!point.is_zero(), "G1 infinity is forbidden");
    ensure!(point.is_on_curve(), "G1 point is not on curve");
    ensure!(
        point.is_in_correct_subgroup_assuming_on_curve(),
        "G1 point is not in the prime-order subgroup"
    );
    Ok(point)
}

fn decode_g2(bytes: &[u8]) -> Result<G2Affine> {
    ensure!(bytes.len() == 128, "G2 point must be exactly 128 bytes");
    let point = G2Affine::new_unchecked(
        Fq2::new(decode_fq(&bytes[..32])?, decode_fq(&bytes[32..64])?),
        Fq2::new(decode_fq(&bytes[64..96])?, decode_fq(&bytes[96..])?),
    );
    ensure!(!point.is_zero(), "G2 infinity is forbidden");
    ensure!(point.is_on_curve(), "G2 point is not on curve");
    ensure!(
        point.is_in_correct_subgroup_assuming_on_curve(),
        "G2 point is not in the prime-order subgroup"
    );
    Ok(point)
}

fn encode_verifying_key(key: &VerifyingKey<Bn254>) -> Result<Vec<u8>> {
    ensure!(
        key.gamma_abc_g1.len() == 7,
        "verifying key must bind six public inputs"
    );
    let mut bytes = Vec::with_capacity(PARAMETERS_LEN);
    encode_g1(&key.alpha_g1, &mut bytes)?;
    encode_g2(&key.beta_g2, &mut bytes)?;
    encode_g2(&key.gamma_g2, &mut bytes)?;
    encode_g2(&key.delta_g2, &mut bytes)?;
    for point in &key.gamma_abc_g1 {
        encode_g1(point, &mut bytes)?;
    }
    ensure!(
        bytes.len() == VK_LEN,
        "verifying key must be exactly 896 bytes"
    );
    Ok(bytes)
}

fn decode_verifying_key(bytes: &[u8]) -> Result<VerifyingKey<Bn254>> {
    ensure!(
        bytes.len() == VK_LEN,
        "verifying key must be exactly 896 bytes"
    );
    let alpha_g1 = decode_g1(&bytes[..64])?;
    let beta_g2 = decode_g2(&bytes[64..192])?;
    let gamma_g2 = decode_g2(&bytes[192..320])?;
    let delta_g2 = decode_g2(&bytes[320..448])?;
    let gamma_abc_g1 = bytes[448..]
        .as_chunks::<64>()
        .0
        .iter()
        .map(|point| decode_g1(point))
        .collect::<Result<Vec<_>>>()?;
    Ok(VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    })
}
