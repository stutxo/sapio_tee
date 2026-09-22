//! Validated, deterministic fixed-key preparation, performed before funding.
//!
//! Prepared coefficients are public but not self-authenticating: canonical
//! decoding cannot establish their relation to a source VK. Both entrypoints
//! use this producer to validate every source point and derive the tables before
//! the module and entire parameter encoding determine the funding key. Existing
//! funded outputs are not upgraded, and no witness may supply prepared tables.

use anyhow::{ensure, Context, Result};
use substrate_bn::{
    arith::U256, AffineG1, AffineG2, Fq, Fq2, Fr, Group, PreparedPairing, G1, G2,
    PREPARED_PAIRING_BYTES,
};

const RAW_FIXED_KEY_BYTES: usize = 64 + 3 * 128;
const IC_BYTES: usize = 7 * 64;
const RAW_VK_BYTES: usize = RAW_FIXED_KEY_BYTES + IC_BYTES;
const RAW_PARAMETERS_BYTES: usize = RAW_VK_BYTES + 32;
// G16M || Montgomery pairing || tagged folded IC (65) || IC3..IC6 (256) || C (32).
pub const PREPARED_PARAMETERS_BYTES: usize = 4 + PREPARED_PAIRING_BYTES + 65 + 4 * 64 + 32;

/// Accept only the original 928-byte VK || C format, never prepared parameters.
/// This has no proof, witness, or transaction input and is not a spend verifier.
pub fn prepare_parameters(raw: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        raw.len() == RAW_PARAMETERS_BYTES,
        "source parameters must be exactly {RAW_PARAMETERS_BYTES} bytes"
    );
    let alpha = read_g1(&raw[..64]).context("decoding source alpha")?;
    let beta = read_g2(&raw[64..192]).context("decoding source beta")?;
    let gamma = read_g2(&raw[192..320]).context("decoding source gamma")?;
    let delta = read_g2(&raw[320..RAW_FIXED_KEY_BYTES]).context("decoding source delta")?;
    let mut ic = [G1::zero(); 7];
    for (index, bytes) in raw[RAW_FIXED_KEY_BYTES..RAW_VK_BYTES]
        .as_chunks::<64>()
        .0
        .iter()
        .enumerate()
    {
        ic[index] = read_g1(bytes).with_context(|| format!("decoding source IC{index}"))?;
    }
    // Fold only fixed, validated contract data. C stays in the parameter encoding
    // as the public commitment, but its two scalar contributions are prepaid.
    let mut folded = ic[0];
    for (index, half) in raw[RAW_VK_BYTES..].as_chunks::<16>().0.iter().enumerate() {
        let mut scalar = [0u8; 32];
        scalar[16..].copy_from_slice(half);
        let public = Fr::new(
            U256::from_slice(&scalar)
                .ok()
                .context("commitment scalar width")?,
        )
        .context("noncanonical commitment scalar")?;
        folded = folded + ic[index + 1] * public;
    }
    // PreparedPairing revalidates its fixed points internally as well.
    let prepared = PreparedPairing::prepare(alpha, beta, gamma, delta)
        .context("preparing validated fixed pairing key")?;
    let mut output = vec![0u8; PREPARED_PARAMETERS_BYTES];
    output[..4].copy_from_slice(b"G16M");
    prepared
        .encode(&mut output[4..4 + PREPARED_PAIRING_BYTES])
        .context("encoding prepared pairing key")?;
    let folded_offset = 4 + PREPARED_PAIRING_BYTES;
    if let Some(point) = AffineG1::from_jacobian(folded) {
        output[folded_offset] = 1;
        point
            .x()
            .to_big_endian(&mut output[folded_offset + 1..folded_offset + 33])
            .ok()
            .context("encoding folded IC x")?;
        point
            .y()
            .to_big_endian(&mut output[folded_offset + 33..folded_offset + 65])
            .ok()
            .context("encoding folded IC y")?;
    }
    // A computed infinity has the unique tag=0, coordinates=0 representation.
    // Original source points, including IC0..IC6, still cannot encode infinity.
    output[folded_offset + 65..].copy_from_slice(&raw[RAW_FIXED_KEY_BYTES + 3 * 64..]);
    Ok(output)
}

fn read_fq(bytes: &[u8]) -> Result<Fq> {
    Fq::from_slice(bytes)
        .ok()
        .context("noncanonical source Fq coordinate")
}

fn read_g1(bytes: &[u8]) -> Result<G1> {
    // All callsites provide exactly 64 bytes. Affine construction checks the
    // curve; BN254 G1 has cofactor one, establishing subgroup membership too.
    let point: G1 = AffineG1::new(read_fq(&bytes[..32])?, read_fq(&bytes[32..])?)
        .ok()
        .context("source G1 is not on curve")?
        .into();
    ensure!(!point.is_zero(), "source G1 infinity is forbidden");
    Ok(point)
}

fn read_g2(bytes: &[u8]) -> Result<G2> {
    // c0 || c1 is not Fq2::from_slice's radix-q encoding. Check each canonical
    // Fq limb separately, then the twist equation and prime-order subgroup.
    let x = Fq2::new(read_fq(&bytes[..32])?, read_fq(&bytes[32..64])?);
    let y = Fq2::new(read_fq(&bytes[64..96])?, read_fq(&bytes[96..])?);
    let point: G2 = AffineG2::new(x, y)
        .ok()
        .context("source G2 is off curve or outside the prime-order subgroup")?
        .into();
    ensure!(!point.is_zero(), "source G2 infinity is forbidden");
    Ok(point)
}

#[test]
fn commitment_folding_preserves_cancellation_without_admitting_source_infinity() {
    let corpus: checkzkp_prover::fixtures::Corpus =
        serde_json::from_slice(include_bytes!("../../fixtures/corpus.json")).unwrap();
    let mut raw = corpus
        .cases
        .into_iter()
        .find(|case| case.expected == checkzkp_prover::fixtures::Expected::Accept)
        .unwrap()
        .parameters;
    let ic1 = read_g1(&raw[RAW_FIXED_KEY_BYTES + 64..RAW_FIXED_KEY_BYTES + 128]).unwrap();
    let opposite = AffineG1::from_jacobian(-ic1).unwrap();
    opposite
        .x()
        .to_big_endian(&mut raw[RAW_FIXED_KEY_BYTES..RAW_FIXED_KEY_BYTES + 32])
        .unwrap();
    opposite
        .y()
        .to_big_endian(&mut raw[RAW_FIXED_KEY_BYTES + 32..RAW_FIXED_KEY_BYTES + 64])
        .unwrap();
    raw[RAW_VK_BYTES..].fill(0);
    raw[RAW_VK_BYTES + 15] = 1; // C_hi=1, C_lo=0: IC0 + IC1 cancels.
    let offset = 4 + PREPARED_PAIRING_BYTES;
    let prepared = prepare_parameters(&raw).unwrap();
    assert_eq!(&prepared[offset..offset + 65], &[0; 65]);
    raw[RAW_VK_BYTES + 15] = 0;
    let prepared = prepare_parameters(&raw).unwrap();
    assert_eq!(prepared[offset], 1);
    assert_eq!(read_g1(&prepared[offset + 1..offset + 65]).unwrap(), -ic1);
    raw[RAW_FIXED_KEY_BYTES..RAW_FIXED_KEY_BYTES + 64].fill(0);
    assert!(prepare_parameters(&raw).is_err());
}
