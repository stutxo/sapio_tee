//! Native prover for the public, fixed-length M31 recurrence experiment.
//!
//! There are no credentials, secret inputs, signing operations, or privacy
//! claims. The context digest only binds this public computation's transcript.

mod trace;

use anyhow::{anyhow, Context, Result};
use checkstwo_verifier::air::{preprocessed_ids, RecurrenceEval, LOG_SIZE};
use checkstwo_verifier::{
    encode_parameters, encode_witness, mix_statement, pcs_config, verify_proof, Parameters, Proof,
};
use stwo::core::channel::Blake2sChannel;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo::core::pcs::TreeVec;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::poly::twiddles::TwiddleTree;
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::{
    assert_constraints_on_trace, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

/// A native-verified proof encoded using the guest's exact wire format.
pub struct Fixture {
    pub parameters: Vec<u8>,
    pub witness: Vec<u8>,
    pub preprocessed_root: [u8; 32],
    pub output: [u32; 2],
    pub log_size: u32,
}

fn twiddles() -> TwiddleTree<SimdBackend> {
    let lifting_log_size = pcs_config()
        .lifting_log_size
        .expect("the fixed recurrence preset specifies a lifting size");
    SimdBackend::precompute_twiddles(
        CanonicCoset::new(lifting_log_size)
            .circle_domain()
            .half_coset,
    )
}

fn check_trace(
    preprocessed: &trace::Columns<2>,
    execution: &trace::Columns<3>,
    initial: [u32; 2],
    output: [u32; 2],
) {
    let columns = TreeVec::new(vec![
        preprocessed.iter().collect(),
        execution.iter().collect(),
    ]);
    // Check the actual shared AIR on every row, including the two boundary
    // selectors and the non-wrapping final transition. A violated constraint
    // is a programming error, not an accepted or silently repaired witness.
    assert_constraints_on_trace(
        &columns,
        LOG_SIZE,
        |row| {
            RecurrenceEval {
                initial: initial.map(M31),
                output: output.map(M31),
            }
            .evaluate(row);
        },
        QM31::from(0),
    );
}

/// Checks native arithmetic against an independent integer implementation and
/// evaluates the actual AIR without constructing a STARK proof.
///
/// Inputs at or above the M31 modulus are rejected rather than reduced.
pub fn check_computation(initial: [u32; 2]) -> Result<[u32; 2]> {
    let (execution, output) = trace::execution(initial)?;
    check_trace(&trace::preprocessed(), &execution, initial, output);
    Ok(output)
}

/// Computes the fixed selector-tree commitment used by the verifier preset.
/// This depends only on the public AIR layout and PCS configuration.
pub fn preprocessed_root() -> Result<[u8; 32]> {
    let twiddles = twiddles();
    let mut channel = Blake2sChannel::default();
    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(pcs_config(), &twiddles);
    let mut tree = scheme.tree_builder();
    tree.extend_evals(trace::evaluations(trace::preprocessed()));
    tree.commit(&mut channel);
    Ok(scheme.roots()[0].0)
}

/// Proves exactly 1023 transitions `(a, b) -> (b, a*a + b*b)` over M31.
///
/// The initial state, final state, and caller-provided context digest are
/// public. No zero-knowledge property is requested or asserted.
pub fn prove_computation(initial: [u32; 2], context: &[u8; 32]) -> Result<Fixture> {
    let (execution, output) = trace::execution(initial)?;
    let preprocessed = trace::preprocessed();
    check_trace(&preprocessed, &execution, initial, output);

    let parameters = Parameters { initial };
    let twiddles = twiddles();
    let mut channel = Blake2sChannel::default();
    mix_statement(&mut channel, &parameters, context, &output);
    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(pcs_config(), &twiddles);
    let mut tree = scheme.tree_builder();
    tree.extend_evals(trace::evaluations(preprocessed));
    tree.commit(&mut channel);
    let preprocessed_root = scheme.roots()[0].0;
    let mut tree = scheme.tree_builder();
    tree.extend_evals(trace::evaluations(execution));
    tree.commit(&mut channel);

    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_ids());
    let component = FrameworkComponent::new(
        &mut allocator,
        RecurrenceEval {
            initial: initial.map(M31),
            output: output.map(M31),
        },
        QM31::from(0),
    );
    let stark = prove::<SimdBackend, Blake2sMerkleChannel>(&[&component], &mut channel, scheme)
        .context("proving the public recurrence")?;
    let proof = Proof { output, stark };
    let witness = encode_witness(&proof);
    verify_proof(&parameters, context, proof, preprocessed_root)
        .map_err(|error| anyhow!("native STWO verification failed: {error:?}"))?;

    Ok(Fixture {
        parameters: encode_parameters(&parameters),
        witness,
        preprocessed_root,
        output,
        log_size: LOG_SIZE,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::fields::m31::P;
    use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};

    #[test]
    fn public_recurrence_survives_polynomial_proving_and_context_binding() {
        // Independent integer calculation of exactly 1023 transitions.
        // Row-only AIR checks did not detect the earlier lifting mismatch.
        let fixture = prove_computation([3, 5], &[7; 32]).unwrap();
        assert_eq!(fixture.output, [2_058_201_256, 595_859_339]);
        assert!(checkstwo_verifier::verify_bytes(
            &fixture.parameters,
            &[8; 32],
            &fixture.witness,
            fixture.preprocessed_root
        )
        .is_err());
    }

    #[test]
    fn incorrect_interior_witness_fails_with_unchanged_public_endpoints() {
        let initial = [P - 1, P - 1];
        let (mut execution, output) = trace::execution(initial).unwrap();
        let preprocessed = trace::preprocessed();
        check_trace(&preprocessed, &execution, initial, output);

        let interior =
            bit_reverse_index(coset_index_to_circle_domain_index(513, LOG_SIZE), LOG_SIZE);
        execution[1][interior] = execution[1][interior] + M31(1);
        assert!(std::panic::catch_unwind(|| check_trace(
            &preprocessed,
            &execution,
            initial,
            output
        ))
        .is_err());
    }
}
