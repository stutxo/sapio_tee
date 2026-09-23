//! Official arkworks Groth16/BN254 verification entirely in guest WASM.
//!
//! G16A parameters must be derived by this validated producer before funding.
//! Canonical prepared decoding does not authenticate pairing tables against a
//! source VK. The module and complete parameters define a new funding identity;
//! no witness may supply or replace fixed precomputations. Native preparation
//! uses the same arkworks arithmetic as the guest, not an independent backend.
#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

#[cfg(target_arch = "wasm32")]
#[path = "../../../../examples/vault/guest.rs"]
mod guest;

mod codec;
#[cfg(target_arch = "wasm32")]
mod wasm;

use alloc::vec::Vec;
use ark_bn254::{Bn254, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_groth16::{prepare_verifying_key, VerifyingKey};
use codec::{
    read_g1, read_g2, read_scalar_half, write_fq12, write_g1, write_g2, write_lines, Reader,
};

const RAW_FIXED_KEY_BYTES: usize = 64 + 3 * 128;
const RAW_VK_BYTES: usize = RAW_FIXED_KEY_BYTES + 7 * 64;
const RAW_PARAMETERS_BYTES: usize = RAW_VK_BYTES + 32;
const LINE_COEFFICIENTS: usize = 87;
const PREPARED_PAIRING_BYTES: usize = 12 * 32 + 2 * LINE_COEFFICIENTS * 6 * 32;
const FIXED_KEY_OFFSET: usize = 4 + PREPARED_PAIRING_BYTES;
const IC_OFFSET: usize = FIXED_KEY_OFFSET + RAW_FIXED_KEY_BYTES;
const COMMITMENT_OFFSET: usize = IC_OFFSET + 65 + 4 * 64;

/// G16A || Montgomery target and negative gamma/delta tables || full Montgomery
/// fixed VK metadata || tagged ordinary folded IC || ordinary IC3..IC6 || C.
pub const PREPARED_PARAMETERS_BYTES: usize = COMMITMENT_OFFSET + 32;

// arkworks' Miller loop consumes one line per loop bit, another for each signed
// nonzero bit, then two final lines. An incompatible loop must never reach its
// internal coefficient-iterator unwraps with a truncated prepared table.
const _: () = {
    let bits = <ark_bn254::Config as ark_ec::bn::BnConfig>::ATE_LOOP_COUNT;
    let mut lines = 2;
    let mut index = 0;
    while index + 1 < bits.len() {
        lines += 1;
        if bits[index] == 1 || bits[index] == -1 {
            lines += 1;
        }
        index += 1;
    }
    assert!(lines == LINE_COEFFICIENTS);
    assert!(PREPARED_PAIRING_BYTES == 33_792);
    assert!(PREPARED_PARAMETERS_BYTES == 34_597);
};

/// Validate the original 928-byte raw VK || C and derive fixed data before
/// funding. This has no proof, witness, or transaction input and is not a spend
/// verifier. All original points must be canonical, on-curve, non-infinity and
/// in the prime-order subgroup, including IC points folded out of the guest VK.
pub fn prepare_parameters(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    if raw.len() != RAW_PARAMETERS_BYTES {
        return Err("source parameters must be exactly 928 bytes");
    }
    let mut reader = Reader::new(&raw[..RAW_VK_BYTES]);
    let alpha_g1 = read_g1(&mut reader).ok_or("invalid source alpha")?;
    let beta_g2 = read_g2(&mut reader).ok_or("invalid source beta")?;
    let gamma_g2 = read_g2(&mut reader).ok_or("invalid source gamma")?;
    let delta_g2 = read_g2(&mut reader).ok_or("invalid source delta")?;
    let mut ic = [G1Affine::identity(); 7];
    for point in &mut ic {
        *point = read_g1(&mut reader).ok_or("invalid source IC point")?;
    }
    if !reader.is_finished() {
        return Err("invalid source VK length");
    }

    let mut folded = ic[0].into_group();
    for (point, half) in ic[1..3].iter().zip(raw[RAW_VK_BYTES..].as_chunks::<16>().0) {
        let public = read_scalar_half(half).ok_or("invalid commitment scalar")?;
        folded += *point * public;
    }
    let folded = folded.into_affine();
    let mut gamma_abc_g1 = Vec::with_capacity(5);
    gamma_abc_g1.push(folded);
    gamma_abc_g1.extend_from_slice(&ic[3..]);
    let vk = VerifyingKey::<Bn254> {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    };
    let prepared = prepare_verifying_key(&vk);
    if prepared.gamma_g2_neg_pc.infinity
        || prepared.delta_g2_neg_pc.infinity
        || prepared.gamma_g2_neg_pc.ell_coeffs.len() != LINE_COEFFICIENTS
        || prepared.delta_g2_neg_pc.ell_coeffs.len() != LINE_COEFFICIENTS
    {
        return Err("incompatible arkworks prepared line tables");
    }

    let mut output = Vec::with_capacity(PREPARED_PARAMETERS_BYTES);
    output.extend_from_slice(b"G16A");
    write_fq12(&mut output, &prepared.alpha_g1_beta_g2);
    write_lines(&mut output, &prepared.gamma_g2_neg_pc);
    write_lines(&mut output, &prepared.delta_g2_neg_pc);
    // Preserve the actual fixed VK, not dummy points in PreparedVerifyingKey.
    write_g1::<true>(&mut output, &prepared.vk.alpha_g1);
    write_g2::<true>(&mut output, &prepared.vk.beta_g2);
    write_g2::<true>(&mut output, &prepared.vk.gamma_g2);
    write_g2::<true>(&mut output, &prepared.vk.delta_g2);
    if folded.infinity {
        // Only a computed IC may be infinity; tag=0 requires 64 zero bytes.
        output.extend_from_slice(&[0; 65]);
    } else {
        output.push(1);
        write_g1::<false>(&mut output, &folded);
    }
    // IC3..IC6 and C retain their original canonical ordinary encodings.
    output.extend_from_slice(&raw[RAW_FIXED_KEY_BYTES + 3 * 64..]);
    if output.len() != PREPARED_PARAMETERS_BYTES {
        return Err("incompatible arkworks prepared encoding length");
    }
    Ok(output)
}
