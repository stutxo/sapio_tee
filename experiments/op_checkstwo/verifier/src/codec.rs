//! Versioned, canonical wire encoding for one fixed AIR and one fixed PCS preset.
//!
//! All integers are little endian. Parameters are `S2RP || initial[2]`.
//! Witnesses are `S2RW || output[2] || PCS[7] || commitments[3] || OODS[15]
//! || tree_decommitments[3] || query_count || queried_columns[13]
//! || proof_of_work || FRI_layers[10] || last_coefficient`.
//! PCS is pow, blowup, last-degree, queries, fold, lifting-present, lifting-size.
//! A decommitment is a u32 count followed by 32-byte hashes. A FRI layer is
//! commitment, decommitment, u32 witness-count, then QM31 witnesses. M31 is one
//! canonical u32 below 2^31-1; QM31 is four M31 limbs in upstream basis order.
//! Dimensions are implicit and cannot be selected by a witness. No serde input
//! reaches STWO. The native diagnostic cap is separate from the guest's 64 KiB.

use alloc::{vec, vec::Vec};
use stwo::core::fields::m31::{M31, P};
use stwo::core::fields::qm31::QM31;
use stwo::core::fri::{FriLayerProof, FriProof};
use stwo::core::pcs::quotients::CommitmentSchemeProof;
use stwo::core::pcs::TreeVec;
use stwo::core::poly::line::LinePoly;
use stwo::core::proof::StarkProof;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
use stwo::core::vcs_lifted::verifier::MerkleDecommitmentLifted;

use crate::{pcs_config, Error, Parameters, Proof, LIFTING_LOG_SIZE, N_QUERIES};

pub const MAX_NATIVE_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const COLUMN_COUNTS: [usize; 3] = [2, 3, 8];
pub(crate) const INNER_LAYERS: usize = 9;

pub(crate) const fn sample_count(tree: usize, column: usize) -> usize {
    if tree == 1 && column < 2 {
        2
    } else {
        1
    }
}

pub fn encode_parameters(parameters: &Parameters) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(12);
    bytes.extend_from_slice(b"S2RP");
    for value in parameters.initial {
        put_u32(&mut bytes, value);
    }
    bytes
}

pub fn decode_parameters(bytes: &[u8]) -> Result<Parameters, Error> {
    let mut reader = Reader::new(bytes)?;
    reader.magic(b"S2RP")?;
    let initial = [reader.m31()?.0, reader.m31()?.0];
    reader.finish()?;
    Ok(Parameters { initial })
}

pub fn encode_witness(proof: &Proof) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"S2RW");
    for value in proof.output {
        put_u32(&mut bytes, value);
    }
    let config = proof.stark.config;
    for value in [
        config.pow_bits,
        config.fri_config.log_blowup_factor,
        config.fri_config.log_last_layer_degree_bound,
        u32::try_from(config.fri_config.n_queries).expect("query count exceeds u32"),
        config.fri_config.fold_step,
        u32::from(config.lifting_log_size.is_some()),
        config.lifting_log_size.unwrap_or(0),
    ] {
        put_u32(&mut bytes, value);
    }
    assert_eq!(proof.stark.commitments.len(), 3, "fixed AIR tree count");
    for root in proof.stark.commitments.iter() {
        bytes.extend_from_slice(&root.0);
    }
    assert_eq!(proof.stark.sampled_values.len(), 3, "fixed OODS trees");
    for (index, (tree, &columns)) in proof
        .stark
        .sampled_values
        .iter()
        .zip(&COLUMN_COUNTS)
        .enumerate()
    {
        assert_eq!(tree.len(), columns, "fixed OODS columns");
        for (column, samples) in tree.iter().enumerate() {
            assert_eq!(
                samples.len(),
                sample_count(index, column),
                "fixed OODS offsets"
            );
            for &value in samples {
                put_qm31(&mut bytes, value);
            }
        }
    }
    assert_eq!(
        proof.stark.decommitments.len(),
        3,
        "fixed decommitment trees"
    );
    for decommitment in proof.stark.decommitments.iter() {
        put_decommitment(&mut bytes, decommitment);
    }
    assert_eq!(proof.stark.queried_values.len(), 3, "fixed query trees");
    let query_count = proof.stark.queried_values[0][0].len();
    put_count(&mut bytes, query_count);
    for (tree, &columns) in proof.stark.queried_values.iter().zip(&COLUMN_COUNTS) {
        assert_eq!(tree.len(), columns, "fixed query columns");
        for column in tree {
            assert_eq!(column.len(), query_count, "uniform lifted query count");
            for &value in column {
                put_u32(&mut bytes, value.0);
            }
        }
    }
    bytes.extend_from_slice(&proof.stark.proof_of_work.to_le_bytes());
    put_layer(&mut bytes, &proof.stark.fri_proof.first_layer);
    assert_eq!(
        proof.stark.fri_proof.inner_layers.len(),
        INNER_LAYERS,
        "fixed FRI depth"
    );
    for layer in &proof.stark.fri_proof.inner_layers {
        put_layer(&mut bytes, layer);
    }
    assert_eq!(
        proof.stark.fri_proof.last_layer_poly.len(),
        1,
        "constant FRI last layer"
    );
    put_qm31(&mut bytes, proof.stark.fri_proof.last_layer_poly[0]);
    bytes
}

pub fn decode_witness(bytes: &[u8]) -> Result<Proof, Error> {
    let mut reader = Reader::new(bytes)?;
    reader.magic(b"S2RW")?;
    let output = [reader.m31()?.0, reader.m31()?.0];
    for expected in [0, 2, 0, N_QUERIES as u32, 1, 1, LIFTING_LOG_SIZE] {
        if reader.u32()? != expected {
            return Err(Error::Configuration);
        }
    }
    let commitments = TreeVec::new(reader.fixed_vec(3, 32, |reader| reader.hash())?);
    let mut sampled_values = Vec::with_capacity(3);
    for (tree, columns) in COLUMN_COUNTS.into_iter().enumerate() {
        let mut sampled_columns = Vec::with_capacity(columns);
        for column in 0..columns {
            sampled_columns
                .push(reader.fixed_vec(sample_count(tree, column), 16, |reader| reader.qm31())?);
        }
        sampled_values.push(sampled_columns);
    }
    let decommitments = TreeVec::new(reader.fixed_vec(3, 4, |reader| {
        reader.decommitment(N_QUERIES * LIFTING_LOG_SIZE as usize)
    })?);
    let query_count = reader.count(N_QUERIES, 13 * 4)?;
    if query_count == 0 {
        return Err(Error::Shape);
    }
    let mut queried_values = Vec::with_capacity(3);
    for columns in COLUMN_COUNTS {
        queried_values.push(reader.fixed_vec(columns, query_count * 4, |reader| {
            reader.fixed_vec(query_count, 4, |reader| reader.m31())
        })?);
    }
    let proof_of_work =
        u64::from_le_bytes(reader.take(8)?.try_into().map_err(|_| Error::Encoding)?);
    let first_layer = reader.layer(LIFTING_LOG_SIZE)?;
    let mut inner_layers = Vec::with_capacity(INNER_LAYERS);
    for i in 0..INNER_LAYERS {
        inner_layers.push(reader.layer(LIFTING_LOG_SIZE - 1 - i as u32)?);
    }
    let last_layer_poly = LinePoly::new(vec![reader.qm31()?]);
    reader.finish()?;
    Ok(Proof {
        output,
        stark: StarkProof(CommitmentSchemeProof {
            config: pcs_config(),
            commitments,
            sampled_values: TreeVec::new(sampled_values),
            decommitments,
            queried_values: TreeVec::new(queried_values),
            proof_of_work,
            fri_proof: FriProof {
                first_layer,
                inner_layers,
                last_layer_poly,
            },
        }),
    })
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_count(bytes: &mut Vec<u8>, count: usize) {
    put_u32(bytes, u32::try_from(count).expect("wire count exceeds u32"));
}

fn put_qm31(bytes: &mut Vec<u8>, value: QM31) {
    for limb in value.to_m31_array() {
        put_u32(bytes, limb.0);
    }
}

fn put_decommitment(bytes: &mut Vec<u8>, proof: &MerkleDecommitmentLifted<Blake2sMerkleHasher>) {
    put_count(bytes, proof.hash_witness.len());
    for hash in &proof.hash_witness {
        bytes.extend_from_slice(&hash.0);
    }
}

fn put_layer(bytes: &mut Vec<u8>, proof: &FriLayerProof<Blake2sMerkleHasher>) {
    bytes.extend_from_slice(&proof.commitment.0);
    put_decommitment(bytes, &proof.decommitment);
    put_count(bytes, proof.fri_witness.len());
    for &value in &proof.fri_witness {
        put_qm31(bytes, value);
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_NATIVE_BYTES {
            return Err(Error::Limit);
        }
        Ok(Self { bytes, offset: 0 })
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(count).ok_or(Error::Limit)?;
        let bytes = self.bytes.get(self.offset..end).ok_or(Error::Encoding)?;
        self.offset = end;
        Ok(bytes)
    }

    fn magic(&mut self, expected: &[u8; 4]) -> Result<(), Error> {
        if self.take(4)? != expected {
            return Err(Error::Encoding);
        }
        Ok(())
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Encoding)?,
        ))
    }

    fn m31(&mut self) -> Result<M31, Error> {
        let value = self.u32()?;
        if value >= P {
            return Err(Error::NonCanonical);
        }
        Ok(M31::from_u32_unchecked(value))
    }

    fn qm31(&mut self) -> Result<QM31, Error> {
        Ok(QM31::from_m31_array([
            self.m31()?,
            self.m31()?,
            self.m31()?,
            self.m31()?,
        ]))
    }

    fn hash(&mut self) -> Result<Blake2sHash, Error> {
        Ok(Blake2sHash(
            self.take(32)?.try_into().map_err(|_| Error::Encoding)?,
        ))
    }

    fn count(&mut self, maximum: usize, element_bytes: usize) -> Result<usize, Error> {
        let count = usize::try_from(self.u32()?).map_err(|_| Error::Limit)?;
        if count > maximum {
            return Err(Error::Limit);
        }
        self.check_bytes(count, element_bytes)?;
        Ok(count)
    }

    fn check_bytes(&self, count: usize, element_bytes: usize) -> Result<(), Error> {
        let needed = count.checked_mul(element_bytes).ok_or(Error::Limit)?;
        if needed > self.bytes.len() - self.offset {
            return Err(Error::Encoding);
        }
        Ok(())
    }

    fn fixed_vec<T>(
        &mut self,
        count: usize,
        element_bytes: usize,
        mut read: impl FnMut(&mut Self) -> Result<T, Error>,
    ) -> Result<Vec<T>, Error> {
        self.check_bytes(count, element_bytes)?;
        let mut values = Vec::new();
        values.try_reserve_exact(count).map_err(|_| Error::Limit)?;
        for _ in 0..count {
            values.push(read(self)?);
        }
        Ok(values)
    }

    fn decommitment(
        &mut self,
        maximum: usize,
    ) -> Result<MerkleDecommitmentLifted<Blake2sMerkleHasher>, Error> {
        let count = self.count(maximum, 32)?;
        Ok(MerkleDecommitmentLifted {
            hash_witness: self.fixed_vec(count, 32, |reader| reader.hash())?,
        })
    }

    fn layer(&mut self, log_domain: u32) -> Result<FriLayerProof<Blake2sMerkleHasher>, Error> {
        let commitment = self.hash()?;
        let decommitment = self.decommitment(2 * N_QUERIES * log_domain as usize)?;
        let count = self.count(N_QUERIES, 16)?;
        let fri_witness = self.fixed_vec(count, 16, |reader| reader.qm31())?;
        Ok(FriLayerProof {
            commitment,
            decommitment,
            fri_witness,
        })
    }

    fn finish(self) -> Result<(), Error> {
        if self.offset != self.bytes.len() {
            return Err(Error::Encoding);
        }
        Ok(())
    }
}
