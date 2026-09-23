//! Public algebraic workloads, not transaction authorization policies. Only generation
//! uses randomness; replay never loads a proving key, witness assignment, or setup state.

use anyhow::{bail, ensure, Context, Result};
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField, UniformRand, Zero};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use checkzkp_generic_guest::{
    G1_BYTES, MAX_ARGUMENT_BYTES, PROOF_BYTES, SCALAR_BYTES, VECTOR_LENGTH_BYTES,
    VK_IC_COUNT_OFFSET,
};
use rand::rngs::OsRng;
use serde::{de, Deserialize, Deserializer, Serialize};
use std::collections::HashSet;
use std::fmt;

pub const REFERENCE_DESCRIPTION: &str = "Native arkworks 0.5 and the native generic core check every label; their arithmetic is the SAME library as the WASM guest, not an independent arithmetic reference. No native prepared key is supplied to WASM.";

#[derive(Debug, Deserialize, Serialize)]
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
    #[serde(
        serialize_with = "hex::serde::serialize",
        deserialize_with = "bounded_hex"
    )]
    pub verifying_key: Vec<u8>,
    #[serde(
        serialize_with = "hex::serde::serialize",
        deserialize_with = "bounded_hex"
    )]
    pub proof: Vec<u8>,
    #[serde(
        serialize_with = "hex::serde::serialize",
        deserialize_with = "bounded_hex"
    )]
    pub public_inputs: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Expected {
    Accept,
    Reject,
    Malformed,
}

impl Expected {
    pub fn name(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Reject => "reject",
            Self::Malformed => "malformed",
        }
    }

    pub fn from_result(result: i32) -> Result<Self> {
        match result {
            1 => Ok(Self::Accept),
            0 => Ok(Self::Reject),
            -1 => Ok(Self::Malformed),
            _ => bail!("unknown groth16_verify_v1 return code {result}"),
        }
    }
}

fn bounded_hex<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<u8>, D::Error> {
    struct HexVisitor;
    impl<'de> de::Visitor<'de> for HexVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(
                formatter,
                "a hex string encoding at most {MAX_ARGUMENT_BYTES} bytes"
            )
        }

        fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Vec<u8>, E> {
            if value.len() > 2 * MAX_ARGUMENT_BYTES {
                return Err(E::custom("hex input exceeds the 65536-byte buffer limit"));
            }
            hex::decode(value).map_err(E::custom)
        }
    }
    deserializer.deserialize_str(HexVisitor)
}

fn encode<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(value.serialized_size(Compress::No));
    value.serialize_with_mode(&mut bytes, Compress::No)?;
    ensure!(
        bytes.len() <= MAX_ARGUMENT_BYTES,
        "fixture buffer exceeds byte limit"
    );
    Ok(bytes)
}

fn decode<T: CanonicalDeserialize + CanonicalSerialize>(bytes: &[u8]) -> Result<T> {
    let mut remaining = bytes;
    let value = T::deserialize_with_mode(&mut remaining, Compress::No, Validate::Yes)?;
    ensure!(remaining.is_empty(), "trailing canonical input bytes");
    // The wire protocol is stricter than Deserialize alone: finite sign-bit
    // aliases and nonzero-coordinate infinity aliases are not canonical output.
    // Native reference allocation is bounded; the WASM core compares streaming.
    ensure!(
        encode(&value)? == bytes,
        "noncanonical point representation"
    );
    Ok(value)
}

// Arkworks' Vec decoder reserves the declared count before reading elements.
// These native-reference checks mirror the public format, not unchecked decoding:
// compare counts to the actual bounded payload BEFORE invoking that decoder.
fn vector_count(bytes: &[u8], offset: usize, element_bytes: usize) -> Result<usize> {
    ensure!(
        bytes.len() <= MAX_ARGUMENT_BYTES,
        "buffer exceeds byte limit"
    );
    let header_end = offset + VECTOR_LENGTH_BYTES;
    ensure!(bytes.len() >= header_end, "truncated vector header");
    let payload = bytes.len() - header_end;
    ensure!(payload % element_bytes == 0, "partial vector element");
    let count = u64::from_le_bytes(bytes[offset..header_end].try_into()?);
    ensure!(
        count == (payload / element_bytes) as u64,
        "vector count/length mismatch"
    );
    Ok(payload / element_bytes)
}

fn parse(fixture: &Fixture) -> Result<(VerifyingKey<Bn254>, Proof<Bn254>, Vec<Fr>)> {
    let key_count = vector_count(&fixture.verifying_key, VK_IC_COUNT_OFFSET, G1_BYTES)?;
    let input_count = vector_count(&fixture.public_inputs, 0, SCALAR_BYTES)?;
    ensure!(
        key_count != 0 && key_count == input_count + 1,
        "invalid IC/input arity"
    );
    ensure!(
        fixture.proof.len() == PROOF_BYTES,
        "incorrect proof byte length"
    );
    Ok((
        decode(&fixture.verifying_key)?,
        decode(&fixture.proof)?,
        decode(&fixture.public_inputs)?,
    ))
}

pub fn verify_fixture(fixture: &Fixture) -> Result<()> {
    let native = match parse(fixture) {
        Ok((key, proof, inputs)) => {
            match Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&key), &proof, &inputs) {
                Ok(true) => Expected::Accept,
                Ok(false) => Expected::Reject,
                Err(_) => Expected::Malformed,
            }
        }
        Err(_) => Expected::Malformed,
    };
    ensure!(
        native == fixture.expected,
        "upstream native result {native:?} disagrees with expected {:?}",
        fixture.expected
    );
    let core = match checkzkp_generic_guest::verify(
        &fixture.verifying_key,
        &fixture.proof,
        &fixture.public_inputs,
    ) {
        Ok(true) => Expected::Accept,
        Ok(false) => Expected::Reject,
        Err(_) => Expected::Malformed,
    };
    ensure!(
        core == fixture.expected,
        "native generic core result {core:?} disagrees with expected {:?}",
        fixture.expected
    );
    Ok(())
}

pub fn validate(corpus: &Corpus) -> Result<&Fixture> {
    ensure!(
        corpus.format_version == 1,
        "unsupported corpus format version {}",
        corpus.format_version
    );
    let mut names = HashSet::new();
    let mut accepted = None;
    let mut has_rejection = false;
    let mut has_malformed = false;
    for fixture in &corpus.cases {
        ensure!(!fixture.name.is_empty(), "empty fixture name");
        ensure!(
            names.insert(fixture.name.as_str()),
            "duplicate fixture name {:?}",
            fixture.name
        );
        ensure!(
            [
                &fixture.verifying_key,
                &fixture.proof,
                &fixture.public_inputs
            ]
            .iter()
            .all(|bytes| bytes.len() <= MAX_ARGUMENT_BYTES),
            "fixture {:?} exceeds buffer bounds",
            fixture.name,
        );
        match fixture.expected {
            Expected::Accept => {
                accepted.get_or_insert(fixture);
            }
            Expected::Reject => has_rejection = true,
            Expected::Malformed => has_malformed = true,
        }
        verify_fixture(fixture).with_context(|| format!("checking fixture {:?}", fixture.name))?;
    }
    ensure!(has_rejection, "corpus has no false-equation case");
    ensure!(has_malformed, "corpus has no malformed case");
    accepted.context("corpus has no accepted case")
}

#[derive(Clone)]
struct AlgebraicCircuit {
    roots: Vec<Fr>,
    inputs: Vec<Fr>,
    blind: Fr,
    unused_last: bool,
}

impl AlgebraicCircuit {
    fn fresh(constrained: usize, unused_last: bool, rng: &mut OsRng) -> Self {
        let mut roots: Vec<Fr> = (0..constrained).map(|_| Fr::rand(rng)).collect();
        if constrained == 1 {
            // Its square is 9 * 2^200, strictly above 128 bits and below Fr's
            // modulus. This is a constrained public value, not an unused one.
            roots[0] = Fr::from(3u64) * Fr::from(2u64).pow([100u64]);
        }
        let mut inputs: Vec<Fr> = roots.iter().map(Field::square).collect();
        if unused_last {
            // A full canonical scalar, intentionally not limited to 128 bits.
            inputs.push(-Fr::from(7u64));
        }
        Self {
            roots,
            inputs,
            blind: Fr::rand(rng),
            unused_last,
        }
    }
}

impl ConstraintSynthesizer<Fr> for AlgebraicCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> std::result::Result<(), SynthesisError> {
        if self.inputs.len() != self.roots.len() + usize::from(self.unused_last) {
            return Err(SynthesisError::Unsatisfiable);
        }
        let public = self
            .inputs
            .iter()
            .map(|value| cs.new_input_variable(|| Ok(*value)))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        // Keep even the zero-public-input relation nonempty.
        let hidden = cs.new_witness_variable(|| Ok(self.blind))?;
        let square = cs.new_witness_variable(|| Ok(self.blind.square()))?;
        cs.enforce_constraint(lc!() + hidden, lc!() + hidden, lc!() + square)?;
        for (root, input) in self.roots.iter().zip(public) {
            let witness = cs.new_witness_variable(|| Ok(*root))?;
            cs.enforce_constraint(lc!() + witness, lc!() + witness, lc!() + input)?;
        }
        Ok(())
    }
}

fn fresh_fixture(name: &str, circuit: AlgebraicCircuit, rng: &mut OsRng) -> Result<Fixture> {
    let proving_key =
        Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit.clone(), rng)
            .context("fresh local experimental setup (not a production ceremony)")?;
    prove_fixture(name, circuit, &proving_key, rng)
}

fn prove_fixture(
    name: &str,
    circuit: AlgebraicCircuit,
    proving_key: &ProvingKey<Bn254>,
    rng: &mut OsRng,
) -> Result<Fixture> {
    let inputs = circuit.inputs.clone();
    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(circuit, proving_key, rng)?;
    ensure!(
        Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&proving_key.vk), &proof, &inputs)?,
        "fresh proof failed official verification"
    );
    Ok(Fixture {
        name: name.to_owned(),
        expected: Expected::Accept,
        verifying_key: encode(&proving_key.vk)?,
        proof: encode(&proof)?,
        public_inputs: encode(&inputs)?,
    })
}

fn altered(
    base: &Fixture,
    name: &str,
    expected: Expected,
    mutate: impl FnOnce(&mut Fixture),
) -> Fixture {
    let mut fixture = base.clone();
    fixture.name = name.to_owned();
    fixture.expected = expected;
    mutate(&mut fixture);
    fixture
}

fn wrong_subgroup_g2() -> Result<Vec<u8>> {
    // Sampling a prime-order group API would clear the cofactor. Search the
    // twist directly, with a bounded deterministic search on PUBLIC data.
    for candidate in 0..1024u64 {
        let x = Fq2::new(Fq::from(candidate), Fq::from(1u64));
        let Some(point) = G2Affine::get_point_from_x_unchecked(x, false) else {
            continue;
        };
        if point.is_in_correct_subgroup_assuming_on_curve() {
            continue;
        }
        ensure!(
            point.is_on_curve() && !point.is_zero(),
            "invalid twist point"
        );
        ensure!(
            !point.mul_bigint(Fr::MODULUS).is_zero(),
            "subgroup negative has prime order"
        );
        let bytes = encode(&point)?;
        ensure!(
            decode::<G2Affine>(&bytes).is_err(),
            "upstream validated decoder accepted wrong subgroup"
        );
        return Ok(bytes);
    }
    bail!("could not construct a wrong-subgroup twist point")
}

fn malformed_cases(base: &Fixture, cases: &mut Vec<Fixture>) -> Result<()> {
    for (name, select) in [("vk", 0), ("proof", 1), ("inputs", 2)] {
        for trailing in [false, true] {
            let suffix = if trailing {
                "trailing_byte"
            } else {
                "truncated_byte"
            };
            cases.push(altered(
                base,
                &format!("malformed_{name}_{suffix}"),
                Expected::Malformed,
                |case| {
                    let bytes = match select {
                        0 => &mut case.verifying_key,
                        1 => &mut case.proof,
                        _ => &mut case.public_inputs,
                    };
                    if trailing {
                        bytes.push(0);
                    } else {
                        bytes.pop();
                    }
                },
            ));
        }
    }
    cases.push(altered(
        base,
        "malformed_vk_hostile_count",
        Expected::Malformed,
        |case| {
            case.verifying_key
                .truncate(VK_IC_COUNT_OFFSET + VECTOR_LENGTH_BYTES);
            case.verifying_key[VK_IC_COUNT_OFFSET..].copy_from_slice(&u64::MAX.to_le_bytes());
        },
    ));
    cases.push(altered(
        base,
        "malformed_inputs_hostile_count",
        Expected::Malformed,
        |case| {
            case.public_inputs = u64::MAX.to_le_bytes().to_vec();
        },
    ));
    cases.push(altered(
        base,
        "malformed_empty_ic",
        Expected::Malformed,
        |case| {
            case.verifying_key
                .truncate(VK_IC_COUNT_OFFSET + VECTOR_LENGTH_BYTES);
            case.verifying_key[VK_IC_COUNT_OFFSET..].fill(0);
            case.public_inputs = 0u64.to_le_bytes().to_vec();
        },
    ));
    cases.push(altered(
        base,
        "malformed_input_key_arity",
        Expected::Malformed,
        |case| {
            // Both vectors individually have correct byte lengths/counts.
            case.public_inputs = 0u64.to_le_bytes().to_vec();
        },
    ));
    cases.push(altered(
        base,
        "malformed_vk_declared_count",
        Expected::Malformed,
        |case| {
            case.verifying_key[VK_IC_COUNT_OFFSET..VK_IC_COUNT_OFFSET + VECTOR_LENGTH_BYTES]
                .copy_from_slice(&3u64.to_le_bytes());
        },
    ));
    cases.push(altered(
        base,
        "malformed_inputs_declared_count",
        Expected::Malformed,
        |case| {
            case.public_inputs[..VECTOR_LENGTH_BYTES].fill(0);
        },
    ));
    let fr_modulus = Fr::MODULUS.to_bytes_le();
    cases.push(altered(
        base,
        "malformed_noncanonical_fr",
        Expected::Malformed,
        |case| {
            case.public_inputs[VECTOR_LENGTH_BYTES..VECTOR_LENGTH_BYTES + SCALAR_BYTES]
                .copy_from_slice(&fr_modulus);
        },
    ));
    let fq_modulus = Fq::MODULUS.to_bytes_le();
    cases.push(altered(
        base,
        "malformed_proof_noncanonical_fq",
        Expected::Malformed,
        |case| {
            case.proof[..SCALAR_BYTES].copy_from_slice(&fq_modulus);
        },
    ));
    cases.push(altered(
        base,
        "malformed_vk_noncanonical_fq",
        Expected::Malformed,
        |case| {
            case.verifying_key[..SCALAR_BYTES].copy_from_slice(&fq_modulus);
        },
    ));
    cases.push(altered(
        base,
        "malformed_proof_off_curve_g1",
        Expected::Malformed,
        |case| {
            // Zero coordinates with NO infinity flag are not the identity encoding.
            case.proof[..G1_BYTES].fill(0);
        },
    ));
    cases.push(altered(
        base,
        "malformed_vk_off_curve_ic",
        Expected::Malformed,
        |case| {
            case.verifying_key[VK_IC_COUNT_OFFSET + VECTOR_LENGTH_BYTES..][..G1_BYTES].fill(0);
        },
    ));
    cases.push(altered(
        base,
        "malformed_proof_off_curve_g2",
        Expected::Malformed,
        |case| {
            case.proof[G1_BYTES..3 * G1_BYTES].fill(0);
        },
    ));
    let wrong_subgroup = wrong_subgroup_g2()?;
    cases.push(altered(
        base,
        "malformed_proof_g2_subgroup",
        Expected::Malformed,
        |case| {
            case.proof[G1_BYTES..3 * G1_BYTES].copy_from_slice(&wrong_subgroup);
        },
    ));
    cases.push(altered(
        base,
        "malformed_vk_g2_subgroup",
        Expected::Malformed,
        |case| {
            // gamma_g2, not just the first fixed point, must be validated.
            case.verifying_key[3 * G1_BYTES..5 * G1_BYTES].copy_from_slice(&wrong_subgroup);
        },
    ));
    // Deserialize alone accepts these aliases. The public byte-canonical
    // protocol deliberately rejects them without banning canonical infinity.
    cases.push(altered(
        base,
        "malformed_proof_g1_sign_alias",
        Expected::Malformed,
        |case| {
            case.proof[G1_BYTES - 1] ^= 0x80;
        },
    ));
    cases.push(altered(
        base,
        "malformed_vk_g2_sign_alias",
        Expected::Malformed,
        |case| {
            case.verifying_key[3 * G1_BYTES - 1] ^= 0x80;
        },
    ));
    let mut g1_alias = encode(&G1Affine::identity())?;
    g1_alias[0] = 1;
    cases.push(altered(
        base,
        "malformed_vk_infinity_coordinate_alias",
        Expected::Malformed,
        |case| {
            case.verifying_key[VK_IC_COUNT_OFFSET + VECTOR_LENGTH_BYTES..][..G1_BYTES]
                .copy_from_slice(&g1_alias);
        },
    ));
    let mut g2_alias = encode(&G2Affine::identity())?;
    g2_alias[0] = 1;
    cases.push(altered(
        base,
        "malformed_proof_infinity_coordinate_alias",
        Expected::Malformed,
        |case| {
            case.proof[G1_BYTES..3 * G1_BYTES].copy_from_slice(&g2_alias);
        },
    ));
    Ok(())
}

pub fn generate() -> Result<Corpus> {
    let mut rng = OsRng;
    let mut cases = Vec::new();
    for count in [0usize, 1, 6, 32] {
        let circuit = AlgebraicCircuit::fresh(count, false, &mut rng);
        cases.push(fresh_fixture(
            &format!("algebraic_{count}_inputs"),
            circuit,
            &mut rng,
        )?);
    }
    let one = cases[1].clone();
    let six = cases[2].clone();
    let thirty_two = cases[3].clone();
    let circuit = AlgebraicCircuit::fresh(1, false, &mut rng);
    let independent = fresh_fixture("independent_setup_1_input", circuit, &mut rng)?;
    cases.push(altered(
        &one,
        "wrong_independent_key",
        Expected::Reject,
        |case| {
            case.verifying_key.clone_from(&independent.verifying_key);
        },
    ));
    cases.push(independent);
    for (base, index, name) in [
        (&six, 0, "constrained_input_mutation"),
        (&thirty_two, 31, "last_of_32_inputs_mutation"),
    ] {
        let mut inputs: Vec<Fr> = decode(&base.public_inputs)?;
        inputs[index] += Fr::from(1u64);
        let bytes = encode(&inputs)?;
        cases.push(altered(base, name, Expected::Reject, |case| {
            case.public_inputs = bytes;
        }));
    }
    let mut proof: Proof<Bn254> = decode(&one.proof)?;
    proof.c = (proof.c.into_group() + G1Affine::generator()).into_affine();
    ensure!(
        proof.c.is_on_curve() && proof.c.is_in_correct_subgroup_assuming_on_curve(),
        "proof mutation left prime-order group"
    );
    let proof = encode(&proof)?;
    cases.push(altered(
        &one,
        "prime_order_proof_mutation",
        Expected::Reject,
        |case| {
            case.proof = proof;
        },
    ));
    // Official LibsnarkReduction includes input-consistency rows even for
    // variables absent from R1CS constraints. Regenerate the proof for the
    // changed unused input rather than claiming the original must still work.
    let mut unused_circuit = AlgebraicCircuit::fresh(1, true, &mut rng);
    let unused_key = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        unused_circuit.clone(),
        &mut rng,
    )?;
    cases.push(prove_fixture(
        "unused_r1cs_input_original",
        unused_circuit.clone(),
        &unused_key,
        &mut rng,
    )?);
    unused_circuit.inputs[1] += Fr::from(1u64);
    cases.push(prove_fixture(
        "unused_r1cs_input_changed_fresh_proof",
        unused_circuit,
        &unused_key,
        &mut rng,
    )?);

    // Separately test identity IC semantics using an explicitly algebraically
    // constructed key, NOT a key claimed to come from a production setup.
    // Extending a zero-input VK with identity leaves the verifier equation
    // unchanged for every scalar; reuse exactly the original zero-input proof.
    let mut identity = cases[0].clone();
    let mut key: VerifyingKey<Bn254> = decode(&identity.verifying_key)?;
    key.gamma_abc_g1.push(G1Affine::identity());
    identity.name = "algebraically_constructed_identity_ic".to_owned();
    identity.verifying_key = encode(&key)?;
    identity.public_inputs = encode(&vec![-Fr::from(7u64)])?;
    let changed_inputs = encode(&vec![-Fr::from(6u64)])?;
    let changed = altered(
        &identity,
        "algebraically_constructed_identity_ic_changed_same_proof",
        Expected::Accept,
        |case| {
            case.public_inputs = changed_inputs;
        },
    );
    cases.push(identity);
    cases.push(changed);
    malformed_cases(&one, &mut cases)?;
    let corpus = Corpus {
        format_version: 1,
        cases,
    };
    validate(&corpus)?;
    Ok(corpus)
}
