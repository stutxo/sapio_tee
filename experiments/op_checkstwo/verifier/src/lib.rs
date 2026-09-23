//! Public-computation STWO verifier feasibility experiment, not authorization.
//!
//! This crate verifies one fixed recurrence AIR using the unmodified STWO 2.3.0
//! core verifier. All inputs and outputs are public. Neither privacy nor a
//! production security level is claimed. The trusted preprocessing root is an
//! explicit caller input; the WASM guest pins it in its module, never its witness.
//!
//! Transcript reconstruction follows StarkWare's Apache-2.0 STWO core verifier,
//! PCS and FRI implementations at commit 3e233e8fbb4cf2bedd33806960eb6980745f1b32:
//! https://github.com/starkware-libs/stwo/tree/3e233e8fbb4cf2bedd33806960eb6980745f1b32/crates/stwo/src/core
//! The recurrence constraints and bounded wire format are local to this experiment.
#![no_std]

extern crate alloc;

pub mod air;
mod codec;

use alloc::vec::Vec;
use core::fmt;
use stwo::core::channel::{Blake2sChannel, Channel, MerkleChannel};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::{M31, P};
use stwo::core::fields::qm31::QM31;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::proof::StarkProof;
use stwo::core::queries::draw_queries;
use stwo::core::vcs::blake2_hash::{Blake2sHash, Blake2sHasher};
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

pub use air::LOG_SIZE;
pub use codec::{
    decode_parameters, decode_witness, encode_parameters, encode_witness, MAX_NATIVE_BYTES,
};
pub const N_STEPS: usize = air::N_TRANSITIONS;
pub const DOMAIN: &[u8] = b"sapio/checkstwo/public-recurrence/v1";
pub const N_QUERIES: usize = 64;
pub const LIFTING_LOG_SIZE: u32 = LOG_SIZE + 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameters {
    pub initial: [u32; 2],
}

#[derive(Clone, Debug)]
pub struct Proof {
    pub output: [u32; 2],
    pub stark: StarkProof<Blake2sMerkleHasher>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Encoding,
    NonCanonical,
    Limit,
    Configuration,
    Shape,
    PreprocessedRoot,
    Verification,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Encoding => "invalid or trailing STWO encoding",
            Self::NonCanonical => "noncanonical M31 field element",
            Self::Limit => "STWO decoding resource limit",
            Self::Configuration => "unexpected STWO configuration",
            Self::Shape => "unexpected STWO proof dimensions",
            Self::PreprocessedRoot => "unexpected fixed preprocessing root",
            Self::Verification => "STWO proof rejected",
        })
    }
}

impl core::error::Error for Error {}

pub fn pcs_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 0,
        fri_config: FriConfig::new(0, 2, N_QUERIES, 1),
        lifting_log_size: Some(LIFTING_LOG_SIZE),
    }
}

/// Bind the fixed protocol, full PCS preset, canonical public endpoints and all
/// 32 context bytes before commitments. `mix_u32s` preserves arbitrary context
/// words as bytes, rather than reducing them modulo the M31 field modulus.
pub fn mix_statement(
    channel: &mut Blake2sChannel,
    parameters: &Parameters,
    context: &[u8; 32],
    output: &[u32; 2],
) {
    Blake2sMerkleChannel::mix_root(channel, Blake2sHasher::hash(DOMAIN));
    pcs_config().mix_into(channel);
    channel.mix_u32s(&[1, LOG_SIZE, N_STEPS as u32]);
    channel.mix_u32s(&[
        parameters.initial[0],
        parameters.initial[1],
        output[0],
        output[1],
    ]);
    let words = core::array::from_fn::<_, 8, _>(|i| {
        u32::from_le_bytes([
            context[4 * i],
            context[4 * i + 1],
            context[4 * i + 2],
            context[4 * i + 3],
        ])
    });
    channel.mix_u32s(&words);
}

pub fn verify_bytes(
    parameters: &[u8],
    context: &[u8; 32],
    witness: &[u8],
    expected_preprocessed_root: [u8; 32],
) -> Result<(), Error> {
    let parameters = decode_parameters(parameters)?;
    let proof = decode_witness(witness)?;
    verify_proof(&parameters, context, proof, expected_preprocessed_root)
}

pub fn verify_proof(
    parameters: &Parameters,
    context: &[u8; 32],
    proof: Proof,
    expected_preprocessed_root: [u8; 32],
) -> Result<(), Error> {
    if parameters
        .initial
        .iter()
        .chain(proof.output.iter())
        .any(|value| *value >= P)
    {
        return Err(Error::NonCanonical);
    }
    validate_shape(&proof.stark)?;
    if proof.stark.commitments[0] != Blake2sHash(expected_preprocessed_root) {
        return Err(Error::PreprocessedRoot);
    }
    let mut channel = Blake2sChannel::default();
    mix_statement(&mut channel, parameters, context, &proof.output);
    let mut commitment_scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(pcs_config());
    commitment_scheme.commit(
        proof.stark.commitments[0],
        &[LOG_SIZE; codec::COLUMN_COUNTS[0]],
        &mut channel,
    );
    commitment_scheme.commit(
        proof.stark.commitments[1],
        &[LOG_SIZE; codec::COLUMN_COUNTS[1]],
        &mut channel,
    );

    // Upstream core 2.3.0 assumes well-shaped query vectors in several indexing
    // and zip_eq operations. Replay only the challenge schedule on a tiny cloned
    // channel to reject malformed counts before any such operation can panic.
    validate_query_shapes(channel.clone(), &proof.stark)?;
    let mut allocator =
        TraceLocationAllocator::new_with_preprocessed_columns(&air::preprocessed_ids());
    let component = FrameworkComponent::new(
        &mut allocator,
        air::RecurrenceEval {
            initial: parameters.initial.map(M31::from_u32_unchecked),
            output: proof.output.map(M31::from_u32_unchecked),
        },
        QM31::from(0),
    );
    stwo::core::verifier::verify_ex::<Blake2sMerkleChannel>(
        &[&component],
        &mut channel,
        &mut commitment_scheme,
        proof.stark,
        true,
    )
    .map_err(|_| Error::Verification)
}

fn canonical(value: &QM31) -> bool {
    value.to_m31_array().iter().all(|limb| limb.0 < P)
}

fn validate_shape(proof: &StarkProof<Blake2sMerkleHasher>) -> Result<(), Error> {
    if proof.config != pcs_config() {
        return Err(Error::Configuration);
    }
    if proof.commitments.len() != 3
        || proof.sampled_values.len() != 3
        || proof.decommitments.len() != 3
        || proof.queried_values.len() != 3
    {
        return Err(Error::Shape);
    }
    for (tree, columns) in codec::COLUMN_COUNTS.into_iter().enumerate() {
        if proof.sampled_values[tree].len() != columns
            || proof.queried_values[tree].len() != columns
        {
            return Err(Error::Shape);
        }
        for (column, samples) in proof.sampled_values[tree].iter().enumerate() {
            if samples.len() != codec::sample_count(tree, column) {
                return Err(Error::Shape);
            }
            if !samples.iter().all(canonical) {
                return Err(Error::NonCanonical);
            }
        }
        for column in &proof.queried_values[tree] {
            if column.is_empty() || column.len() > N_QUERIES {
                return Err(Error::Shape);
            }
            if column.iter().any(|value| value.0 >= P) {
                return Err(Error::NonCanonical);
            }
        }
        if proof.decommitments[tree].hash_witness.len() > N_QUERIES * LIFTING_LOG_SIZE as usize {
            return Err(Error::Shape);
        }
    }
    if proof.fri_proof.inner_layers.len() != codec::INNER_LAYERS
        || proof.fri_proof.last_layer_poly.len() != 1
    {
        return Err(Error::Shape);
    }
    if !canonical(&proof.fri_proof.last_layer_poly[0]) {
        return Err(Error::NonCanonical);
    }
    for (index, layer) in core::iter::once(&proof.fri_proof.first_layer)
        .chain(&proof.fri_proof.inner_layers)
        .enumerate()
    {
        if layer.fri_witness.len() > N_QUERIES
            || layer.decommitment.hash_witness.len()
                > 2 * N_QUERIES * (LIFTING_LOG_SIZE as usize - index)
        {
            return Err(Error::Shape);
        }
        if !layer.fri_witness.iter().all(canonical) {
            return Err(Error::NonCanonical);
        }
    }
    Ok(())
}

/// Number of sibling hashes consumed by an ordinary binary Merkle proof for
/// sorted, unique leaves. Heights and leaves here are verifier-derived only.
fn hash_count(positions: &[usize], height: u32) -> usize {
    let mut positions = positions.to_vec();
    let mut result = 0;
    for _ in 0..height {
        let mut read = 0;
        let mut write = 0;
        while read < positions.len() {
            let position = positions[read];
            if read + 1 < positions.len() && positions[read + 1] == (position ^ 1) {
                read += 2;
            } else {
                result += 1;
                read += 1;
            }
            positions[write] = position >> 1;
            write += 1;
        }
        positions.truncate(write);
    }
    result
}

fn validate_query_shapes(
    mut channel: Blake2sChannel,
    proof: &StarkProof<Blake2sMerkleHasher>,
) -> Result<(), Error> {
    channel.draw_secure_felt(); // composition aggregation coefficient
    Blake2sMerkleChannel::mix_root(&mut channel, proof.commitments[2]);
    CirclePoint::<QM31>::get_random_point(&mut channel); // OODS point
    let samples: Vec<_> = proof
        .sampled_values
        .iter()
        .flat_map(|tree| tree.iter())
        .flat_map(|column| column.iter().copied())
        .collect();
    channel.mix_felts(&samples);
    channel.draw_secure_felt(); // quotient aggregation coefficient
    for layer in core::iter::once(&proof.fri_proof.first_layer).chain(&proof.fri_proof.inner_layers)
    {
        Blake2sMerkleChannel::mix_root(&mut channel, layer.commitment);
        channel.draw_secure_felt();
    }
    channel.mix_felts(&proof.fri_proof.last_layer_poly);
    if !channel.verify_pow_nonce(pcs_config().pow_bits, proof.proof_of_work) {
        return Err(Error::Verification);
    }
    channel.mix_u64(proof.proof_of_work);
    let mut positions = draw_queries(&mut channel, LIFTING_LOG_SIZE, N_QUERIES);
    positions.sort_unstable();
    positions.dedup();
    let expected_hashes = hash_count(&positions, LIFTING_LOG_SIZE);
    for tree in 0..3 {
        if proof.decommitments[tree].hash_witness.len() != expected_hashes
            || proof.queried_values[tree]
                .iter()
                .any(|column| column.len() != positions.len())
        {
            return Err(Error::Shape);
        }
    }
    for (index, layer) in core::iter::once(&proof.fri_proof.first_layer)
        .chain(&proof.fri_proof.inner_layers)
        .enumerate()
    {
        let mut expanded = Vec::with_capacity(2 * positions.len());
        for &position in &positions {
            if expanded.last().copied() != Some(position | 1) {
                expanded.extend_from_slice(&[position & !1, position | 1]);
            }
        }
        if layer.fri_witness.len() != expanded.len() - positions.len()
            || layer.decommitment.hash_witness.len()
                != hash_count(&expanded, LIFTING_LOG_SIZE - index as u32)
        {
            return Err(Error::Shape);
        }
        positions.clear();
        positions.extend(expanded.chunks_exact(2).map(|pair| pair[0] >> 1));
    }
    Ok(())
}
