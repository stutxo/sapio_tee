//! An inline v1 predicate allowing only a complete, capped-fee sweep.
#![no_std]

mod guest;
use guest::{Arguments, Reader};

#[no_mangle]
pub extern "C" fn sapio_evaluate_v1(
    program_pointer: u32,
    program_length: u32,
    parameters_pointer: u32,
    parameters_length: u32,
    view_pointer: u32,
    view_length: u32,
    witness_pointer: u32,
    witness_length: u32,
) -> i32 {
    guest::evaluate(
        [
            program_pointer,
            program_length,
            parameters_pointer,
            parameters_length,
            view_pointer,
            view_length,
            witness_pointer,
            witness_length,
        ],
        evaluate,
    )
}

fn evaluate(arguments: Arguments<'_>) -> Option<bool> {
    let Arguments {
        program,
        parameters,
        view,
        witness,
    } = arguments;
    // The WASM bytes are the inline evaluator; there is no secondary program
    // or authorization witness. Anyone may request a sweep satisfying this rule.
    if !program.is_empty() || !witness.is_empty() {
        return None;
    }

    // Commitment parameters: max_fee:u64LE || script_len:u32LE || script.
    let mut params = Reader::new(parameters);
    let max_fee = u64::from_le_bytes(params.take(8)?.try_into().ok()?);
    let destination_length = params.u32()?;
    let destination = params.take(destination_length as usize)?;
    if !params.is_finished() {
        return None;
    }

    // The v1 view contains transaction fields and supplied prevouts, not chain state.
    let mut reader = Reader::new(view);
    reader.take(8)?; // Transaction version and locktime, four bytes each.
    let selected_index = reader.u32()?;
    let input_count = reader.u32()?;
    if selected_index != 0 || input_count != 1 {
        return Some(false);
    }
    reader.take(36)?; // Input outpoint: txid and output index.
    reader.take(4)?; // Input sequence.
    let input_value = u64::from_le_bytes(reader.take(8)?.try_into().ok()?);
    let input_script_length = reader.u32()?;
    reader.take(input_script_length as usize)?;

    let output_count = reader.u32()?;
    if output_count != 1 {
        return Some(false);
    }
    let output_value = u64::from_le_bytes(reader.take(8)?.try_into().ok()?);
    let output_script_length = reader.u32()?;
    let output_script = reader.take(output_script_length as usize)?;
    if !reader.is_finished() {
        return None;
    }

    // Exactly one output sends the entire input, less a bounded nonnegative
    // fee, to the committed script. There is no change or partial withdrawal.
    // The output must clear the 330-satoshi P2TR dust floor: a sweep always
    // pays a standard, spendable output, so an under-proportioned deposit
    // cannot be burned entirely to fees by the permissionless settler.
    let Some(fee) = input_value.checked_sub(output_value) else {
        return Some(false);
    };
    Some(output_script == destination && output_value >= 330 && fee <= max_fee)
}
