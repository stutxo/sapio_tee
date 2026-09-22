//! Public, replayable authorization fixtures. Only `generate` uses OS randomness;
//! replay decodes public bytes and never needs a secret, proving key, or setup RNG.

use super::{
    decode_g1, decode_g2, decode_verifying_key, encode_g1, encode_g2, public_inputs,
    transaction_digest, DemoProver, PARAMETERS_LEN, PROOF_LEN, VK_LEN, WITNESS_LEN,
};
use anyhow::{bail, ensure, Context, Result};
use ark_bn254::{g2::Config as G2Config, Bn254, Fq, Fq2, Fr, G2Affine};
use ark_ec::{short_weierstrass::SWCurveConfig, AffineRepr};
use ark_ff::{Field, PrimeField, Zero};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Corpus {
    pub format_version: u32,
    pub cases: Vec<Fixture>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {
    pub name: String,
    pub expected: Expected,
    pub kind: Kind,
    #[serde(with = "hex::serde")]
    pub parameters: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub view: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub witness: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Expected {
    Accept,
    Reject,
    Malformed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Full,
    Malformed,
}

/// Perform two independent local setups and produce only public replay data.
/// This is a one-time operation, not part of any benchmark invocation. Neither
/// the `DemoProver` instances nor their secret/proving-key fields are serialized.
pub fn generate() -> Result<Corpus> {
    let mut cases = Vec::new();
    for setup in 0..2 {
        let prover = DemoProver::new()?;
        for variant in 0..2 {
            let (view, amount_offset, destination_offset) = synthetic_view(setup, variant);
            let witness = prover.prove(&view)?;
            let valid = Fixture {
                name: format!("setup_{}_view_{}_valid", setup + 1, variant + 1),
                expected: Expected::Accept,
                kind: Kind::Full,
                parameters: prover.parameters(),
                view,
                witness,
            };
            cases.push(valid.clone());
            if variant == 0 {
                full_rejections(&valid, amount_offset, destination_offset, &mut cases)?;
                if setup == 0 {
                    malformed_cases(&valid, amount_offset, &mut cases)?;
                }
            }
        }
    }
    for fixture in &cases {
        verify_fixture(fixture)
            .with_context(|| format!("checking generated fixture {}", fixture.name))?;
    }
    Ok(Corpus {
        format_version: 1,
        cases,
    })
}

/// Independently verify a fixture using arkworks and only its public bytes.
/// Malformed means a strict parsing error, never a pairing/verifier failure.
pub fn verify_fixture(fixture: &Fixture) -> Result<()> {
    ensure!(!fixture.name.is_empty(), "fixture name must not be empty");
    ensure!(
        matches!(
            (fixture.kind, fixture.expected),
            (Kind::Full, Expected::Accept | Expected::Reject)
                | (Kind::Malformed, Expected::Malformed)
        ),
        "fixture kind and expected result disagree"
    );
    let parsed = parse_fixture(fixture);
    if fixture.expected == Expected::Malformed {
        ensure!(parsed.is_err(), "expected a strict parsing error");
        return Ok(());
    }
    let (key, proof, inputs) = parsed.context("strictly parsing public fixture")?;
    let accepted = Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&key), &proof, &inputs)
        .context("verifying public fixture with arkworks")?;
    ensure!(
        accepted == (fixture.expected == Expected::Accept),
        "arkworks result {accepted} disagrees with expected {:?}",
        fixture.expected
    );
    Ok(())
}

fn parse_fixture(fixture: &Fixture) -> Result<(VerifyingKey<Bn254>, Proof<Bn254>, [Fr; 6])> {
    ensure!(
        fixture.parameters.len() == PARAMETERS_LEN,
        "parameters must be exactly 928 bytes"
    );
    ensure!(
        fixture.witness.len() == WITNESS_LEN,
        "witness must be exactly 288 bytes"
    );
    validate_view(&fixture.view)?;
    let proof = Proof::<Bn254> {
        a: decode_g1(&fixture.witness[..64]).context("decoding proof A")?,
        b: decode_g2(&fixture.witness[64..192]).context("decoding proof B")?,
        c: decode_g1(&fixture.witness[192..PROOF_LEN]).context("decoding proof C")?,
    };
    let key = decode_verifying_key(&fixture.parameters[..VK_LEN])?;
    let commitment: [u8; 32] = fixture.parameters[VK_LEN..].try_into()?;
    let authorization: [u8; 32] = fixture.witness[PROOF_LEN..].try_into()?;
    let transaction = transaction_digest(&fixture.view);
    Ok((
        key,
        proof,
        public_inputs(&commitment, &transaction, &authorization),
    ))
}

// Match the complete pinned Sapio v1 projection, not Bitcoin transaction wire
// serialization. Counts/script lengths are little-endian u32, without varints.
// This independently implements the same structural acceptance rules as the
// scored guest, including the ABI view bound and rejection of trailing bytes.
fn validate_view(view: &[u8]) -> Result<()> {
    ensure!(view.len() <= 1_048_576, "view exceeds the v1 ABI bound");
    let mut remaining = view;
    take(&mut remaining, 8)?; // Transaction version and locktime.
    let selected = read_u32(&mut remaining)?;
    let inputs = read_u32(&mut remaining)?;
    ensure!(selected < inputs, "selected input is out of range");
    for _ in 0..inputs {
        take(&mut remaining, 48)?; // Outpoint, sequence, prevout value.
        let length = read_u32(&mut remaining)?;
        take(&mut remaining, length as usize)?;
    }
    let outputs = read_u32(&mut remaining)?;
    for _ in 0..outputs {
        take(&mut remaining, 8)?;
        let length = read_u32(&mut remaining)?;
        take(&mut remaining, length as usize)?;
    }
    ensure!(remaining.is_empty(), "trailing transaction view bytes");
    Ok(())
}

fn take<'a>(remaining: &mut &'a [u8], length: usize) -> Result<&'a [u8]> {
    let bytes = remaining
        .get(..length)
        .context("truncated transaction view")?;
    *remaining = &remaining[length..];
    Ok(bytes)
}

fn read_u32(remaining: &mut &[u8]) -> Result<u32> {
    Ok(u32::from_le_bytes(take(remaining, 4)?.try_into()?))
}

// Provenance: ctv_emulators/src/program/wasm.rs::encode_view at Sapio revision
// c8f4e63123e724dc1144075af8ac0dbd3cf4e0b1, also used by the existing probe.
// The selected prevout is synthetic Taproot; other inputs/outputs are P2WPKH.
// A fixed public script lets candidate modules replay identical view bytes.
// Actual signing separately derives the candidate-specific program funding key.
// The second view selects input one from two inputs and two outputs.
fn synthetic_view(setup: u32, variant: u32) -> (Vec<u8>, usize, usize) {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&2_i32.to_le_bytes());
    bytes.extend_from_slice(&(800_000 + setup * 10 + variant).to_le_bytes());
    bytes.extend_from_slice(&variant.to_le_bytes());
    bytes.extend_from_slice(&(variant + 1).to_le_bytes());
    for input in 0..=variant {
        bytes.extend_from_slice(&[7 + (setup * 4 + variant * 2 + input) as u8; 32]);
        bytes.extend_from_slice(&input.to_le_bytes());
        bytes.extend_from_slice(&0xffff_fffd_u32.to_le_bytes());
        bytes.extend_from_slice(&100_000_u64.to_le_bytes());
        if input == variant {
            bytes.extend_from_slice(&34_u32.to_le_bytes());
            bytes.extend_from_slice(&[0x51, 32]);
            // Public x-only secp256k1 generator; these outputs are never funded.
            bytes.extend_from_slice(&[
                0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
                0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
                0x16, 0xf8, 0x17, 0x98,
            ]);
        } else {
            bytes.extend_from_slice(&22_u32.to_le_bytes());
            bytes.extend_from_slice(&[0, 20]);
            bytes.extend_from_slice(&[0x20 + (setup * 2 + input) as u8; 20]);
        }
    }
    bytes.extend_from_slice(&(variant + 1).to_le_bytes());
    let amount_offset = bytes.len();
    let destination_offset = amount_offset + 8 + 4 + 2;
    for output in 0..=variant {
        bytes.extend_from_slice(&(99_000 - u64::from(variant * 10 + output)).to_le_bytes());
        bytes.extend_from_slice(&22_u32.to_le_bytes());
        bytes.extend_from_slice(&[0, 20]);
        bytes.extend_from_slice(&[0x40 + (setup * 4 + variant * 2 + output) as u8; 20]);
    }
    (bytes, amount_offset, destination_offset)
}

fn altered(
    base: &Fixture,
    suffix: &str,
    expected: Expected,
    mutate: impl FnOnce(&mut Fixture),
) -> Fixture {
    let mut fixture = base.clone();
    fixture.name = format!("{}_{}", base.name.trim_end_matches("_valid"), suffix);
    fixture.expected = expected;
    fixture.kind = if expected == Expected::Malformed {
        Kind::Malformed
    } else {
        Kind::Full
    };
    mutate(&mut fixture);
    fixture
}

fn full_rejections(
    base: &Fixture,
    amount_offset: usize,
    destination_offset: usize,
    cases: &mut Vec<Fixture>,
) -> Result<()> {
    // Negation is another nonzero prime-order point. In odd prime order, with
    // proof B nonzero, replacing A by -A changes the pairing equation rather
    // than failing any parser or relying on an accidentally off-curve mutation.
    let original = decode_g1(&base.witness[..64])?;
    let replacement = -original;
    ensure!(
        replacement != original,
        "proof A must change under negation"
    );
    let mut encoded = Vec::with_capacity(64);
    encode_g1(&replacement, &mut encoded)?;
    ensure!(
        decode_g1(&encoded)? == replacement,
        "invalid replacement proof A"
    );
    cases.push(altered(
        base,
        "proof_a_prime_order_replacement",
        Expected::Reject,
        |f| {
            f.witness[..64].copy_from_slice(&encoded);
        },
    ));
    cases.push(altered(
        base,
        "changed_output_amount",
        Expected::Reject,
        |f| {
            let amount =
                u64::from_le_bytes(f.view[amount_offset..amount_offset + 8].try_into().unwrap());
            f.view[amount_offset..amount_offset + 8].copy_from_slice(&(amount + 1).to_le_bytes());
        },
    ));
    cases.push(altered(
        base,
        "changed_output_destination",
        Expected::Reject,
        |f| {
            f.view[destination_offset] ^= 1;
        },
    ));
    cases.push(altered(base, "changed_commitment", Expected::Reject, |f| {
        f.parameters[VK_LEN] ^= 1;
    }));
    cases.push(altered(
        base,
        "changed_authorization",
        Expected::Reject,
        |f| {
            f.witness[PROOF_LEN] ^= 1;
        },
    ));
    Ok(())
}

fn malformed_cases(base: &Fixture, amount_offset: usize, cases: &mut Vec<Fixture>) -> Result<()> {
    cases.push(altered(
        base,
        "truncated_witness",
        Expected::Malformed,
        |f| {
            f.witness.pop();
        },
    ));
    cases.push(altered(
        base,
        "trailing_witness",
        Expected::Malformed,
        |f| {
            f.witness.push(0);
        },
    ));
    cases.push(altered(
        base,
        "truncated_parameters",
        Expected::Malformed,
        |f| {
            f.parameters.pop();
        },
    ));
    cases.push(altered(
        base,
        "trailing_parameters",
        Expected::Malformed,
        |f| {
            f.parameters.push(0);
        },
    ));
    cases.push(altered(base, "truncated_view", Expected::Malformed, |f| {
        f.view.pop();
    }));
    cases.push(altered(base, "trailing_view", Expected::Malformed, |f| {
        f.view.push(0);
    }));
    cases.push(altered(
        base,
        "truncated_view_header",
        Expected::Malformed,
        |f| {
            f.view.truncate(8);
        },
    ));
    cases.push(altered(
        base,
        "view_selected_input_out_of_range",
        Expected::Malformed,
        |f| {
            f.view[8..12].copy_from_slice(&1_u32.to_le_bytes());
        },
    ));
    cases.push(altered(
        base,
        "view_input_script_length",
        Expected::Malformed,
        |f| {
            f.view[64..68].copy_from_slice(&u32::MAX.to_le_bytes());
        },
    ));
    cases.push(altered(
        base,
        "view_output_script_length",
        Expected::Malformed,
        |f| {
            f.view[amount_offset + 8..amount_offset + 12].copy_from_slice(&u32::MAX.to_le_bytes());
        },
    ));

    let mut modulus = Vec::with_capacity(32);
    for limb in Fq::MODULUS.0.iter().rev() {
        modulus.extend_from_slice(&limb.to_be_bytes());
    }
    // Exercise strict point parsing in both proof and VK, including the final
    // IC point rather than only an early VK header. All-zero affine coordinates
    // are the forbidden infinity sentinel, not a permitted identity encoding.
    for (name, parameters, offset, length) in [
        ("proof_a", false, 0, 64),
        ("proof_b", false, 64, 128),
        ("vk_alpha", true, 0, 64),
        ("vk_beta", true, 64, 128),
        ("vk_ic_6", true, 832, 64),
    ] {
        for (suffix, replacement) in [
            ("coordinate_equal_modulus", modulus.clone()),
            ("infinity", vec![0; length]),
            ("off_curve", {
                // x=0, y=1 (over Fq or Fq2) is canonical but not on BN254's
                // G1/G2 curve. Unlike the infinity case, this is nonzero data.
                let mut point = vec![0; length];
                point[length / 2 + 31] = 1;
                point
            }),
        ] {
            cases.push(altered(
                base,
                &format!("{name}_{suffix}"),
                Expected::Malformed,
                |f| {
                    let bytes = if parameters {
                        &mut f.parameters
                    } else {
                        &mut f.witness
                    };
                    bytes[offset..offset + replacement.len()].copy_from_slice(&replacement);
                },
            ));
        }
    }
    let wrong_subgroup = wrong_subgroup_g2()?;
    for (name, parameters, offset) in [
        ("proof_b", false, 64),
        ("vk_beta", true, 64),
        ("vk_gamma", true, 192),
        ("vk_delta", true, 320),
    ] {
        cases.push(altered(
            base,
            &format!("{name}_wrong_subgroup"),
            Expected::Malformed,
            |f| {
                let bytes = if parameters {
                    &mut f.parameters
                } else {
                    &mut f.witness
                };
                bytes[offset..offset + 128].copy_from_slice(&wrong_subgroup);
            },
        ));
    }
    Ok(())
}

fn wrong_subgroup_g2() -> Result<Vec<u8>> {
    // Search the twist directly using field square roots. Sampling through a
    // prime-order group API would clear the cofactor and miss this attack.
    // The deterministic search concerns public malformed data only, never setup
    // randomness. Bound the search so an unexpected curve/API change fails.
    for candidate in 0..1024_u64 {
        let x = Fq2::new(Fq::from(candidate), Fq::from(1_u64));
        let Some(y) = (x.square() * x + G2Config::COEFF_B).sqrt() else {
            continue;
        };
        let point = G2Affine::new_unchecked(x, y);
        ensure!(
            !point.is_zero() && point.is_on_curve(),
            "invalid twist square root"
        );
        if point.is_in_correct_subgroup_assuming_on_curve() {
            continue;
        }
        ensure!(
            !point.mul_bigint(Fr::MODULUS).is_zero(),
            "wrong-subgroup point unexpectedly has prime order"
        );
        let mut encoded = Vec::with_capacity(128);
        encode_g2(&point, &mut encoded)?;
        ensure!(
            decode_g2(&encoded).is_err(),
            "strict decoder accepted wrong subgroup"
        );
        return Ok(encoded);
    }
    bail!("could not construct an on-curve G2 point outside the prime-order subgroup")
}
