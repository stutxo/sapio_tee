//! A BIP-446 OP_TEMPLATEHASH emulation predicate (inline v1 ABI).
//!
//! The program commitment is the 32-byte template hash the spending
//! transaction must produce. The oracle signs only that exact transaction:
//! BIP-446 commits nVersion, nLockTime, sha_sequences, sha_outputs and the
//! input index, deliberately NOT the prevouts, scripts or amounts, so the
//! funding may be co-spent with any other inputs and overfunding pays fees
//! instead of stranding coins. The v1 view carries no annex, so this
//! emulates the common annex-absent case (annex_present = 0).
#![no_std]

#[path = "../vault/guest.rs"]
mod guest;
use guest::{hash, Arguments, Reader};

const TAG: &[u8] = b"TemplateHash";
const DIGEST: usize = 32;
// tag_hash || tag_hash || preimage; preimage is 4+4+32+32+1+4 = 77 bytes.
const HASH_MSG_CAPACITY: usize = 2 * DIGEST + 77;

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

/// Scratch inside the bounded input arena, disjoint from the argument slices.
fn scratch(length: usize) -> Option<&'static mut [u8]> {
    let pointer = guest::sapio_alloc_v1(u32::try_from(length).ok()?);
    if pointer == 0 || length == 0 {
        return None;
    }
    Some(unsafe { core::slice::from_raw_parts_mut(pointer as *mut u8, length) })
}

/// Bitcoin compactSize for script lengths inside CTxOut serialization.
fn push_compact_size(buffer: &mut [u8], offset: usize, length: u32) -> Option<usize> {
    if length < 253 {
        *buffer.get_mut(offset)? = length as u8;
        Some(offset + 1)
    } else if length <= 0xFFFF {
        let into = buffer.get_mut(offset..offset + 3)?;
        into[0] = 0xFD;
        into[1..].copy_from_slice(&(length as u16).to_le_bytes());
        Some(offset + 3)
    } else {
        let into = buffer.get_mut(offset..offset + 5)?;
        into[0] = 0xFE;
        into[1..].copy_from_slice(&length.to_le_bytes());
        Some(offset + 5)
    }
}

fn evaluate(args: Arguments<'_>) -> Option<bool> {
    // The only commitment is the 32-byte template hash; no witness evidence.
    if !args.program.is_empty() || !args.witness.is_empty() {
        return None;
    }
    let committed: &[u8; DIGEST] = args.parameters.try_into().ok()?;

    let mut view = Reader::new(args.view);
    let header = view.take(16)?;
    let input_index = u32::from_le_bytes(header[8..12].try_into().ok()?);
    let input_count = u32::from_le_bytes(header[12..16].try_into().ok()?) as usize;
    if input_index as usize >= input_count {
        return None;
    }

    // sha_sequences: SHA256 over every input's 4-byte sequence, per BIP341.
    let sequences = scratch(4 * input_count)?;
    for slot in sequences.chunks_exact_mut(4) {
        view.take(36)?; // outpoint
        slot.copy_from_slice(view.take(4)?);
        view.take(8)?; // value
        let script_length = view.u32()? as usize;
        view.take(script_length)?;
    }

    // sha_outputs: SHA256 over every output's CTxOut serialization
    // (8-byte value || compactSize script length || script), per BIP341.
    let output_count = view.u32()? as usize;
    let outputs = scratch(args.view.len())?;
    let mut used = 0usize;
    for _ in 0..output_count {
        let value = view.take(8)?;
        let script_length = view.u32()?;
        let script = view.take(script_length as usize)?;
        outputs
            .get_mut(used..used + 8)?
            .copy_from_slice(value);
        used += 8;
        used = push_compact_size(outputs, used, script_length)?;
        outputs
            .get_mut(used..used + script.len())?
            .copy_from_slice(script);
        used += script.len();
    }
    if !view.is_finished() {
        return None;
    }

    let mut sha_sequences = [0u8; DIGEST];
    hash(sequences, &mut sha_sequences)?;
    let mut sha_outputs = [0u8; DIGEST];
    hash(&outputs[..used], &mut sha_outputs)?;
    let mut tag_hash = [0u8; DIGEST];
    hash(TAG, &mut tag_hash)?;

    // Tagged hash per BIP340: SHA256(tag_hash || tag_hash || message), where
    // the message is nVersion || nLockTime || sha_sequences || sha_outputs ||
    // annex_present(0) || input_index, per BIP446.
    let mut message = [0u8; HASH_MSG_CAPACITY];
    message[..DIGEST].copy_from_slice(&tag_hash);
    message[DIGEST..2 * DIGEST].copy_from_slice(&tag_hash);
    let body = &mut message[2 * DIGEST..];
    body[..8].copy_from_slice(&header[..8]);
    body[8..40].copy_from_slice(&sha_sequences);
    body[40..72].copy_from_slice(&sha_outputs);
    body[72] = 0; // annex_present: the v1 view has no annex
    body[73..77].copy_from_slice(&input_index.to_le_bytes());
    let mut digest = [0u8; DIGEST];
    hash(&message, &mut digest)?;

    Some(&digest == committed)
}
