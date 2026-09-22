//! Validated, deterministic fixed-key preparation, performed before funding.
//!
//! Prepared coefficients are public but not self-authenticating: canonical
//! decoding cannot establish their relation to a source VK. Both entrypoints
//! use this producer to validate every source point and derive the tables before
//! the module and entire parameter encoding determine the funding key. Existing
//! funded outputs are not upgraded, and no witness may supply prepared tables.

use anyhow::{ensure, Context, Result};
use substrate_bn::{
    AffineG1, AffineG2, Fq, Fq2, Group, PreparedPairing, PREPARED_PAIRING_BYTES, G1, G2,
};

const RAW_FIXED_KEY_BYTES: usize = 64 + 3 * 128;
const IC_BYTES: usize = 7 * 64;
const RAW_VK_BYTES: usize = RAW_FIXED_KEY_BYTES + IC_BYTES;
const RAW_PARAMETERS_BYTES: usize = RAW_VK_BYTES + 32;
pub const PREPARED_PARAMETERS_BYTES: usize = 4 + PREPARED_PAIRING_BYTES + IC_BYTES + 32;

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
    for (index, bytes) in raw[RAW_FIXED_KEY_BYTES..RAW_VK_BYTES]
        .chunks_exact(64)
        .enumerate()
    {
        read_g1(bytes).with_context(|| format!("decoding source IC{index}"))?;
    }
    // PreparedPairing also validates its fixed points internally. IC validation
    // above is mandatory even though its original encoding is copied verbatim.
    let prepared = PreparedPairing::prepare(alpha, beta, gamma, delta)
        .context("preparing validated fixed pairing key")?;
    let mut output = vec![0u8; PREPARED_PARAMETERS_BYTES];
    output[..4].copy_from_slice(b"G16P");
    prepared
        .encode(&mut output[4..4 + PREPARED_PAIRING_BYTES])
        .context("encoding prepared pairing key")?;
    output[4 + PREPARED_PAIRING_BYTES..].copy_from_slice(&raw[RAW_FIXED_KEY_BYTES..]);
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
