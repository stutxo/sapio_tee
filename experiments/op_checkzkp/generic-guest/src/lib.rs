//! Generic BN254 Groth16 proof checking with unchanged arkworks 0.5 arithmetic.
//!
//! The three arguments are exact, canonical, uncompressed arkworks encodings of
//! `VerifyingKey<Bn254>`, `Proof<Bn254>`, and `Vec<Fr>`. Verification includes key
//! validation and cold preparation on every call. This primitive does not bind a
//! key or statement to a transaction and is not, by itself, spend authorization.
#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

#[cfg(target_arch = "wasm32")]
mod wasm;

use alloc::vec::Vec;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate, Write};
use ark_std::io;
use core::fmt;

/// Independent upper bound on each encoded argument.
pub const MAX_ARGUMENT_BYTES: usize = 65_536;
/// Width of an arkworks sequence length, encoded as a little-endian `u64`.
pub const VECTOR_LENGTH_BYTES: usize = 8;
/// Uncompressed BN254 G1 point width, including flags in the last byte.
pub const G1_BYTES: usize = 64;
/// Uncompressed BN254 G2 point width, including flags in the last byte.
pub const G2_BYTES: usize = 128;
/// Full canonical BN254 scalar width; scalars are not reduced from input bytes.
pub const SCALAR_BYTES: usize = 32;
/// `Proof<Bn254>` is G1 A, G2 B, G1 C, without a sequence prefix.
pub const PROOF_BYTES: usize = G1_BYTES + G2_BYTES + G1_BYTES;
/// `VerifyingKey<Bn254>` starts with alpha G1 and beta/gamma/delta G2.
pub const VK_IC_COUNT_OFFSET: usize = G1_BYTES + 3 * G2_BYTES;
/// Fixed key fields followed by the IC vector's length prefix.
pub const VK_PREFIX_BYTES: usize = VK_IC_COUNT_OFFSET + VECTOR_LENGTH_BYTES;

/// The encoded argument to which a failure applies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Argument {
    VerifyingKey,
    Proof,
    PublicInputs,
}

impl fmt::Display for Argument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::VerifyingKey => "verifying key",
            Self::Proof => "proof",
            Self::PublicInputs => "public inputs",
        })
    }
}

/// Malformed protocol data or an error reported by the official verifier.
/// A correctly encoded proof with a false verification equation is `Ok(false)`,
/// never one of these errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyError {
    ArgumentTooLarge(Argument),
    InvalidLength(Argument),
    EmptyVerifyingKey,
    InputCountMismatch { ic_count: usize, input_count: usize },
    InvalidEncoding(Argument),
    NonCanonicalEncoding(Argument),
    VerificationFailed,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArgumentTooLarge(argument) => {
                write!(
                    formatter,
                    "{argument} exceeds the {MAX_ARGUMENT_BYTES}-byte limit"
                )
            }
            Self::InvalidLength(argument) => {
                write!(
                    formatter,
                    "{argument} has an invalid length or sequence count"
                )
            }
            Self::EmptyVerifyingKey => formatter.write_str("verifying key has no IC points"),
            Self::InputCountMismatch {
                ic_count,
                input_count,
            } => write!(
                formatter,
                "verifying key has {ic_count} IC points for {input_count} public inputs"
            ),
            Self::InvalidEncoding(argument) => {
                write!(formatter, "{argument} fails arkworks validated decoding")
            }
            Self::NonCanonicalEncoding(argument) => {
                write!(formatter, "{argument} is not canonically encoded")
            }
            Self::VerificationFailed => {
                formatter.write_str("arkworks verification returned an error")
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl std::error::Error for VerifyError {}

/// Verify an arbitrary BN254 Groth16 statement using canonical uncompressed
/// arkworks 0.5 encodings. Every argument is limited to [`MAX_ARGUMENT_BYTES`].
///
/// Sequence lengths are checked against the bounded buffers before upstream
/// deserialization can allocate. Points are checked on-curve and in-subgroup by
/// `Validate::Yes`; canonical identities are allowed, including unused IC points.
/// A zero-input statement is encoded as an eight-byte zero sequence length and
/// requires exactly one IC point. No application policy or digest is implicit.
pub fn verify(
    verifying_key: &[u8],
    proof: &[u8],
    public_inputs: &[u8],
) -> Result<bool, VerifyError> {
    for (argument, bytes) in [
        (Argument::VerifyingKey, verifying_key),
        (Argument::Proof, proof),
        (Argument::PublicInputs, public_inputs),
    ] {
        if bytes.len() > MAX_ARGUMENT_BYTES {
            return Err(VerifyError::ArgumentTooLarge(argument));
        }
    }
    if proof.len() != PROOF_BYTES {
        return Err(VerifyError::InvalidLength(Argument::Proof));
    }
    let ic_count = preflight_vector(
        verifying_key,
        VK_IC_COUNT_OFFSET,
        G1_BYTES,
        Argument::VerifyingKey,
    )?;
    let input_count = preflight_vector(public_inputs, 0, SCALAR_BYTES, Argument::PublicInputs)?;
    if ic_count == 0 {
        return Err(VerifyError::EmptyVerifyingKey);
    }
    if ic_count - 1 != input_count {
        return Err(VerifyError::InputCountMismatch {
            ic_count,
            input_count,
        });
    }

    let key: VerifyingKey<Bn254> = decode_exact(verifying_key, Argument::VerifyingKey)?;
    require_canonical(&key, verifying_key, Argument::VerifyingKey)?;
    let proof_value: Proof<Bn254> = decode_exact(proof, Argument::Proof)?;
    require_canonical(&proof_value, proof, Argument::Proof)?;
    // Upstream Fr decoding uses from_bigint, not modular reduction. Unlike
    // uncompressed points, its encoding has no ignored sign/infinity flags.
    let inputs: Vec<Fr> = decode_exact(public_inputs, Argument::PublicInputs)?;

    // Preparation deliberately remains here, inside every metered WASM call.
    // The upstream API owns its clone; release the original before verification.
    let prepared = prepare_verifying_key(&key);
    drop(key);
    Groth16::<Bn254>::verify_proof(&prepared, &proof_value, &inputs)
        .map_err(|_| VerifyError::VerificationFailed)
}

fn preflight_vector(
    bytes: &[u8],
    count_offset: usize,
    element_bytes: usize,
    argument: Argument,
) -> Result<usize, VerifyError> {
    let prefix_bytes = count_offset + VECTOR_LENGTH_BYTES;
    let count_bytes = bytes
        .get(count_offset..prefix_bytes)
        .ok_or(VerifyError::InvalidLength(argument))?;
    let declared = u64::from_le_bytes(
        count_bytes
            .try_into()
            .map_err(|_| VerifyError::InvalidLength(argument))?,
    );
    let payload_bytes = bytes.len() - prefix_bytes;
    let actual = payload_bytes / element_bytes;
    // Derive the count from bounded bytes rather than multiplying an untrusted
    // u64 or narrowing it to wasm32 usize. This also rejects trailing bytes.
    if payload_bytes % element_bytes != 0 || declared != actual as u64 {
        return Err(VerifyError::InvalidLength(argument));
    }
    Ok(actual)
}

fn decode_exact<T: CanonicalDeserialize>(
    bytes: &[u8],
    argument: Argument,
) -> Result<T, VerifyError> {
    let mut reader = bytes;
    let value = T::deserialize_with_mode(&mut reader, Compress::No, Validate::Yes)
        .map_err(|_| VerifyError::InvalidEncoding(argument))?;
    if !reader.is_empty() {
        return Err(VerifyError::InvalidLength(argument));
    }
    Ok(value)
}

fn require_canonical<T: CanonicalSerialize>(
    value: &T,
    bytes: &[u8],
    argument: Argument,
) -> Result<(), VerifyError> {
    // ark-ec 0.5 uncompressed decoding ignores a finite point's sign flag and
    // discards infinity coordinates. Validate::Yes alone accepts these aliases.
    // Let the upstream serializer define the one canonical representation,
    // comparing its output as a stream without allocating another encoded key.
    let mut comparison = CanonicalComparison { remaining: bytes };
    value
        .serialize_with_mode(&mut comparison, Compress::No)
        .map_err(|_| VerifyError::NonCanonicalEncoding(argument))?;
    if !comparison.remaining.is_empty() {
        return Err(VerifyError::NonCanonicalEncoding(argument));
    }
    Ok(())
}

struct CanonicalComparison<'a> {
    remaining: &'a [u8],
}

impl Write for CanonicalComparison<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining.get(..bytes.len()) != Some(bytes) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.remaining = &self.remaining[bytes.len()..];
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
