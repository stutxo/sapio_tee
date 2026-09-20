//! Research-only, stateless batch-or-refund settlement predicate.
#![no_std]

// Reuse the existing bounded upstream ABI adapter; do not fork its parser.
#[path = "../vault/guest.rs"]
mod guest;
use guest::{Arguments, Reader};

#[no_mangle]
pub extern "C" fn sapio_evaluate_v1(
    pp: u32,
    pl: u32,
    ap: u32,
    al: u32,
    vp: u32,
    vl: u32,
    wp: u32,
    wl: u32,
) -> i32 {
    guest::evaluate([pp, pl, ap, al, vp, vl, wp, wl], evaluate)
}

fn u64_le(reader: &mut Reader<'_>) -> Option<u64> {
    Some(u64::from_le_bytes(reader.take(8)?.try_into().ok()?))
}

fn evaluate(args: Arguments<'_>) -> Option<bool> {
    if !args.program.is_empty() || !args.witness.is_empty() {
        return None;
    }
    // Domain, cohort nonce, count, denomination, per-person fee cap, then
    // strictly sorted distinct P2TR scripts. EVERY deposit commits ALL payouts.
    let mut params = Reader::new(args.parameters);
    if params.take(4)? != b"CE01" {
        return None;
    }
    params.take(32)?;
    let count = params.u32()? as usize;
    if !(2..=32).contains(&count) {
        return None;
    }
    let denomination = u64_le(&mut params)?;
    let fee_cap = u64_le(&mut params)?;
    let minimum = denomination.checked_sub(fee_cap)?;
    if minimum < 330 || denomination > 2_100_000_000_000_000 {
        return None;
    }
    let scripts = params.take(34 * count)?;
    if !params.is_finished() {
        return None;
    }
    let mut previous: Option<&[u8]> = None;
    for script in scripts.chunks_exact(34) {
        if script[..2] != [0x51, 0x20] || previous.is_some_and(|p| p >= script) {
            return None;
        }
        previous = Some(script);
    }

    let mut view = Reader::new(args.view);
    if view.u32()? != 2 || view.u32()? != 0 {
        return Some(false);
    }
    let selected = view.u32()? as usize;
    if selected >= count || view.u32()? as usize != count {
        return Some(false);
    }
    // A v1 P2TR input is exactly 36+4+8+4+34 bytes. Check the complete
    // bounded region first, then compare earlier outpoints without a scratch
    // table. The script-length check below still rejects other encodings.
    let inputs = view.take(86 * count)?;
    for (index, bytes) in inputs.chunks_exact(86).enumerate() {
        let mut input = Reader::new(bytes);
        let outpoint = input.take(36)?;
        if inputs[..index * 86]
            .chunks_exact(86)
            .any(|previous| &previous[..36] == outpoint)
        {
            return Some(false);
        }
        // RBF enabled; no input-order or participant-to-output mapping.
        if input.u32()? != 0xffff_fffd || u64_le(&mut input)? != denomination {
            return Some(false);
        }
        if input.u32()? != 34 || input.take(34)?[..2] != [0x51, 0x20] {
            return Some(false);
        }
    }
    if view.u32()? as usize != count {
        return Some(false);
    }
    let mut seen = 0u32;
    let mut common_value = None;
    for _ in 0..count {
        let value = u64_le(&mut view)?;
        if value < minimum || value > denomination || common_value.is_some_and(|v| v != value) {
            return Some(false);
        }
        common_value = Some(value);
        if view.u32()? != 34 {
            return Some(false);
        }
        let script = view.take(34)?;
        let Some(index) = scripts
            .chunks_exact(34)
            .position(|expected| expected == script)
        else {
            return Some(false);
        };
        let bit = 1u32 << index;
        if seen & bit != 0 {
            return Some(false);
        }
        seen |= bit;
    }
    // Count distinct members of a count-element roster: a bijection, not the
    // unsafe rule "my payout appears somewhere", which permits shared claims.
    Some(view.is_finished())
}
