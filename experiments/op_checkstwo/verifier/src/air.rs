//! Fixed public recurrence AIR for the STWO feasibility experiment.
//!
//! This is application-specific arithmetic, not a claim of zero knowledge or a
//! general-purpose proof language. Offsets use STWO's natural coset row order.

use alloc::string::ToString;
use stwo::core::fields::m31::M31;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

pub const LOG_SIZE: u32 = 10;
pub const N_ROWS: usize = 1 << LOG_SIZE;
pub const N_TRANSITIONS: usize = N_ROWS - 1;

pub fn preprocessed_ids() -> [PreProcessedColumnId; 2] {
    [
        PreProcessedColumnId {
            id: "first".to_string(),
        },
        PreProcessedColumnId {
            id: "last".to_string(),
        },
    ]
}

#[derive(Clone, Debug)]
pub struct RecurrenceEval {
    pub initial: [M31; 2],
    pub output: [M31; 2],
}

impl FrameworkEval for RecurrenceEval {
    fn log_size(&self) -> u32 {
        LOG_SIZE
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        // An auxiliary square-sum column keeps every constraint quadratic.
        LOG_SIZE + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let [first_id, last_id] = preprocessed_ids();
        let first = eval.get_preprocessed_column(first_id);
        let last = eval.get_preprocessed_column(last_id);
        let [a, next_a] = eval.next_interaction_mask(1, [0, 1]);
        let [b, next_b] = eval.next_interaction_mask(1, [0, 1]);
        let sum = eval.next_trace_mask();
        eval.add_constraint(first.clone() * (a.clone() - E::F::from(self.initial[0])));
        eval.add_constraint(first * (b.clone() - E::F::from(self.initial[1])));
        eval.add_constraint(last.clone() * (a.clone() - E::F::from(self.output[0])));
        eval.add_constraint(last.clone() * (b.clone() - E::F::from(self.output[1])));
        let transition = E::F::from(M31::from(1)) - last;
        eval.add_constraint(transition.clone() * (next_a - b.clone()));
        eval.add_constraint(transition * (next_b - sum.clone()));
        eval.add_constraint(sum - a.clone() * a - b.clone() * b);
        eval
    }
}
