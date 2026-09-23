use anyhow::{ensure, Result};
use checkstwo_verifier::air::LOG_SIZE;
use stwo::core::fields::m31::{M31, P};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;

pub(crate) const N_ROWS: usize = 1 << LOG_SIZE;
pub(crate) type Columns<const N: usize> = [Vec<M31>; N];
pub(crate) type Evaluation = CircleEvaluation<SimdBackend, M31, BitReversedOrder>;

// FrameworkEval's mask offset +1 advances in coset order, not in the storage
// order of a CircleEvaluation. Both the witness and boundary selectors use
// exactly this permutation.
fn storage_index(row: usize) -> usize {
    bit_reverse_index(coset_index_to_circle_domain_index(row, LOG_SIZE), LOG_SIZE)
}

pub(crate) fn preprocessed() -> Columns<2> {
    let mut columns = std::array::from_fn(|_| vec![M31(0); N_ROWS]);
    columns[0][storage_index(0)] = M31(1);
    columns[1][storage_index(N_ROWS - 1)] = M31(1);
    columns
}

pub(crate) fn execution(initial: [u32; 2]) -> Result<(Columns<3>, [u32; 2])> {
    ensure!(
        initial.iter().all(|&x| x < P),
        "initial field elements must be canonical M31 values"
    );
    let mut columns = std::array::from_fn(|_| vec![M31(0); N_ROWS]);
    let mut state = initial.map(M31);
    let mut independent = initial.map(u64::from);
    for row in 0..N_ROWS {
        // This reference computation uses ordinary integer remainder rather
        // than STWO's Mersenne-field reduction or its AIR implementation.
        ensure!(
            state.map(|x| u64::from(x.0)) == independent,
            "native field and independent integer recurrence disagree at row {row}"
        );
        let index = storage_index(row);
        columns[0][index] = state[0];
        columns[1][index] = state[1];
        let sum = state[0] * state[0] + state[1] * state[1];
        columns[2][index] = sum;
        if row + 1 != N_ROWS {
            state = [state[1], sum];
            // Both canonical inputs are below 2^31, so their squared sum fits
            // in u64 without overflow (it is strictly below 2^63).
            independent = [
                independent[1],
                (independent[0] * independent[0] + independent[1] * independent[1]) % u64::from(P),
            ];
        }
    }
    Ok((columns, state.map(|x| x.0)))
}

pub(crate) fn evaluations<const N: usize>(columns: Columns<N>) -> Vec<Evaluation> {
    let domain = CanonicCoset::new(LOG_SIZE).circle_domain();
    columns
        .into_iter()
        .map(|column| CircleEvaluation::new(domain, BaseColumn::from_iter(column)))
        .collect()
}
