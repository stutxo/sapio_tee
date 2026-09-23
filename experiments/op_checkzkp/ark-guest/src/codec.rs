use alloc::vec::Vec;
use ark_bn254::{Config, Fq, Fq12, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::bn::G2Prepared;
use ark_ff::{BigInt, PrimeField};

#[cfg(target_arch = "wasm32")]
use ark_bn254::{Bn254, Fq6};
#[cfg(target_arch = "wasm32")]
use ark_ff::Zero;
#[cfg(target_arch = "wasm32")]
use ark_groth16::{PreparedVerifyingKey, VerifyingKey};

#[cfg(target_arch = "wasm32")]
pub(crate) use crate::guest::Reader;

// The shared guest includes a WASM panic handler and ABI exports. Native
// preparation uses the same bounded Reader operations without those exports.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

#[cfg(not(target_arch = "wasm32"))]
impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(crate) fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(length)?;
        let bytes = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(bytes)
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn read_bigint(reader: &mut Reader<'_>) -> Option<BigInt<4>> {
    let bytes = reader.take(32)?;
    let mut limbs = [0u64; 4];
    for (limb, word) in limbs.iter_mut().rev().zip(bytes.as_chunks::<8>().0) {
        *limb = u64::from_be_bytes(*word);
    }
    Some(BigInt(limbs))
}

fn read_fq(reader: &mut Reader<'_>) -> Option<Fq> {
    // from_bigint rejects ordinary integers >= q instead of reducing them.
    Fq::from_bigint(read_bigint(reader)?)
}

fn read_fq2(reader: &mut Reader<'_>) -> Option<Fq2> {
    Some(Fq2::new(read_fq(reader)?, read_fq(reader)?))
}

pub(crate) fn read_g1(reader: &mut Reader<'_>) -> Option<G1Affine> {
    // Do not use Affine::new: invalid input would assert rather than reject.
    // There is no source/proof infinity token; even (0, 0) must pass the curve
    // equation. BN254 G1's cofactor is one, so its subgroup check is trivial.
    let point = G1Affine::new_unchecked(read_fq(reader)?, read_fq(reader)?);
    (point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve()).then_some(point)
}

pub(crate) fn read_g2(reader: &mut Reader<'_>) -> Option<G2Affine> {
    // Source and proof coordinates use ordinary c0 || c1, never radix-q packing.
    let point = G2Affine::new_unchecked(read_fq2(reader)?, read_fq2(reader)?);
    (point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve()).then_some(point)
}

pub(crate) fn read_scalar_half(bytes: &[u8]) -> Option<Fr> {
    let bytes: &[u8; 16] = bytes.try_into().ok()?;
    let high = u64::from_be_bytes(bytes[..8].try_into().ok()?);
    let low = u64::from_be_bytes(bytes[8..].try_into().ok()?);
    // Every 128-bit half is below r; keep a canonical constructor nonetheless.
    Fr::from_bigint(BigInt([low, high, 0, 0]))
}

fn write_fq<const MONTGOMERY: bool>(output: &mut Vec<u8>, value: &Fq) {
    // ark-ff 0.5.0's public Fp.0 is x*2^256 mod q. Do not call into_bigint on
    // prepared residues: that would undo the native precomputation.
    let integer = if MONTGOMERY {
        value.0
    } else {
        value.into_bigint()
    };
    for limb in integer.0.iter().rev() {
        output.extend_from_slice(&limb.to_be_bytes());
    }
}

fn write_fq2<const MONTGOMERY: bool>(output: &mut Vec<u8>, value: &Fq2) {
    write_fq::<MONTGOMERY>(output, &value.c0);
    write_fq::<MONTGOMERY>(output, &value.c1);
}

pub(crate) fn write_g1<const MONTGOMERY: bool>(output: &mut Vec<u8>, value: &G1Affine) {
    write_fq::<MONTGOMERY>(output, &value.x);
    write_fq::<MONTGOMERY>(output, &value.y);
}

pub(crate) fn write_g2<const MONTGOMERY: bool>(output: &mut Vec<u8>, value: &G2Affine) {
    write_fq2::<MONTGOMERY>(output, &value.x);
    write_fq2::<MONTGOMERY>(output, &value.y);
}

pub(crate) fn write_fq12(output: &mut Vec<u8>, value: &Fq12) {
    // Preserve arkworks' Fq12(c0,c1), Fq6(c0,c1,c2), Fq2(c0,c1) tower order.
    for fq6 in [&value.c0, &value.c1] {
        for fq2 in [&fq6.c0, &fq6.c1, &fq6.c2] {
            write_fq2::<true>(output, fq2);
        }
    }
}

pub(crate) fn write_lines(output: &mut Vec<u8>, value: &G2Prepared<Config>) {
    // EllCoeff tuple order is arkworks' order, not substrate-bn's encoding.
    for (first, second, third) in &value.ell_coeffs {
        for fq2 in [first, second, third] {
            write_fq2::<true>(output, fq2);
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn read_mont_fq(reader: &mut Reader<'_>) -> Option<Fq> {
    let residue = read_bigint(reader)?;
    if residue >= Fq::MODULUS {
        return None;
    }
    // new_unchecked installs an already reduced Montgomery residue directly.
    Some(Fq::new_unchecked(residue))
}

#[cfg(target_arch = "wasm32")]
fn read_mont_fq2(reader: &mut Reader<'_>) -> Option<Fq2> {
    Some(Fq2::new(read_mont_fq(reader)?, read_mont_fq(reader)?))
}

#[cfg(target_arch = "wasm32")]
fn read_mont_fq6(reader: &mut Reader<'_>) -> Option<Fq6> {
    Some(Fq6::new(
        read_mont_fq2(reader)?,
        read_mont_fq2(reader)?,
        read_mont_fq2(reader)?,
    ))
}

#[cfg(target_arch = "wasm32")]
fn read_lines(reader: &mut Reader<'_>) -> Option<G2Prepared<Config>> {
    let mut ell_coeffs = Vec::with_capacity(crate::LINE_COEFFICIENTS);
    for _ in 0..crate::LINE_COEFFICIENTS {
        ell_coeffs.push((
            read_mont_fq2(reader)?,
            read_mont_fq2(reader)?,
            read_mont_fq2(reader)?,
        ));
    }
    Some(G2Prepared {
        ell_coeffs,
        infinity: false,
    })
}

#[cfg(target_arch = "wasm32")]
fn read_fixed_g1(reader: &mut Reader<'_>) -> Option<G1Affine> {
    let x = read_mont_fq(reader)?;
    let y = read_mont_fq(reader)?;
    // Fixed metadata is not used in per-spend arithmetic. Its full curve and
    // subgroup validation belongs to the mandatory pre-funding producer, just
    // like authentication of the fixed pairing tables against the source VK.
    (!(x.is_zero() && y.is_zero())).then_some(G1Affine::new_unchecked(x, y))
}

#[cfg(target_arch = "wasm32")]
fn read_fixed_g2(reader: &mut Reader<'_>) -> Option<G2Affine> {
    let x = read_mont_fq2(reader)?;
    let y = read_mont_fq2(reader)?;
    (!(x.is_zero() && y.is_zero())).then_some(G2Affine::new_unchecked(x, y))
}

#[cfg(target_arch = "wasm32")]
fn read_folded_ic(reader: &mut Reader<'_>) -> Option<G1Affine> {
    match reader.take(1)?[0] {
        0 => reader
            .take(64)?
            .iter()
            .all(|byte| *byte == 0)
            .then_some(G1Affine::identity()),
        1 => read_g1(reader),
        _ => None,
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn read_prepared(reader: &mut Reader<'_>) -> Option<PreparedVerifyingKey<Bn254>> {
    let alpha_g1_beta_g2 = Fq12::new(read_mont_fq6(reader)?, read_mont_fq6(reader)?);
    if alpha_g1_beta_g2.is_zero() {
        return None;
    }
    let gamma_g2_neg_pc = read_lines(reader)?;
    let delta_g2_neg_pc = read_lines(reader)?;
    let alpha_g1 = read_fixed_g1(reader)?;
    let beta_g2 = read_fixed_g2(reader)?;
    let gamma_g2 = read_fixed_g2(reader)?;
    let delta_g2 = read_fixed_g2(reader)?;
    let mut gamma_abc_g1 = Vec::with_capacity(5);
    gamma_abc_g1.push(read_folded_ic(reader)?);
    for _ in 0..4 {
        gamma_abc_g1.push(read_g1(reader)?);
    }
    reader.take(32)?; // C is already folded into gamma_abc_g1[0] before funding.
    if !reader.is_finished() {
        return None;
    }
    Some(PreparedVerifyingKey {
        vk: VerifyingKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        },
        alpha_g1_beta_g2,
        gamma_g2_neg_pc,
        delta_g2_neg_pc,
    })
}
