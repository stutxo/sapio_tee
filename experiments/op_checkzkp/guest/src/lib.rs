//! Experimental Groth16/BN254 verification entirely in guest WASM.
//!
//! Fixed-key pairing data must be derived by validated preparation before funding.
//! The module and all prepared parameters are committed by the funding key; the
//! witness cannot select or replace these tables. Canonical decoding alone does
//! not authenticate arbitrary precomputations against a source verification key.
//! Diagnostic mode never signs and does not change production limits.
#![no_std]

#[path = "../../../../examples/vault/guest.rs"]
mod guest;

use guest::{Arguments, Reader};
use substrate_bn::{
    arith::U256, AffineG1, AffineG2, Fq, Fq2, Fr, Group, PreparedPairing, G1, G2,
    PREPARED_PAIRING_BYTES,
};

const DOMAIN: &[u8] = b"sapio/checkzkp/bn254/v1";
const IC_OFFSET: usize = 4 + PREPARED_PAIRING_BYTES;
const COMMITMENT_OFFSET: usize = IC_OFFSET + 65 + 4 * 64;
const PARAMETERS_BYTES: usize = COMMITMENT_OFFSET + 32;
const PROOF_BYTES: usize = 256;

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
    if !program.is_empty()
        || parameters.len() != PARAMETERS_BYTES
        || parameters.get(..4)? != b"G16M"
        || witness.len() != PROOF_BYTES + 32
    {
        return None;
    }
    validate_view(view)?;
    let mut proof = Reader::new(&witness[..PROOF_BYTES]);
    let a = read_g1(&mut proof)?;
    let b = read_g2(&mut proof)?;
    let c = read_g1(&mut proof)?;
    if !proof.is_finished() {
        return None;
    }

    let mut transcript = [0u8; DOMAIN.len() + 32];
    transcript[..DOMAIN.len()].copy_from_slice(DOMAIN);
    guest::hash(view, &mut transcript[DOMAIN.len()..])?;
    let mut transaction_digest = [0u8; 32];
    guest::hash(&transcript, &mut transaction_digest)?;

    let prepared = PreparedPairing::decode_committed(&parameters[4..4 + PREPARED_PAIRING_BYTES])?;
    let mut vk = Reader::new(&parameters[IC_OFFSET..COMMITMENT_OFFSET]);
    let ic0 = read_folded_ic(&mut vk)?;
    let mut terms = [(G1::zero(), 0u128); 4];
    let mut index = 0;
    // Four dynamic Fr values: the big-endian 128-bit halves of T and A.
    for digest in [transaction_digest.as_slice(), &witness[PROOF_BYTES..]] {
        for half in digest.as_chunks::<16>().0.iter() {
            let mut scalar = [0u8; 32];
            scalar[16..].copy_from_slice(half);
            // Fr::from_slice reduces; Fr::new instead enforces canonical range.
            let public = Fr::new(U256::from_slice(&scalar).ok()?)?;
            // The encoded scalar has at most 128 bits; Fr::new above is retained.
            terms[index] = (read_g1(&mut vk)?, public.into_u256().0[0]);
            index += 1;
        }
    }
    if !vk.is_finished() {
        return None;
    }
    let ic = ic0 + G1::msm_128(&terms);

    // Computed IC values may be zero; encoded proof and source points may not.
    prepared.verify(a, b, c, ic)
}

fn read_folded_ic(reader: &mut Reader<'_>) -> Option<G1> {
    match reader.take(1)?[0] {
        0 => reader
            .take(64)?
            .iter()
            .all(|byte| *byte == 0)
            .then_some(G1::zero()),
        1 => read_g1(reader),
        _ => None,
    }
}

fn read_fq(reader: &mut Reader<'_>) -> Option<Fq> {
    // substrate-bn 0.6.0 rejects 32-byte big-endian integers >= the Fq modulus.
    Fq::from_slice(reader.take(32)?).ok()
}

fn read_g1(reader: &mut Reader<'_>) -> Option<G1> {
    // The affine constructor checks the curve and sets z=1, with no infinity token.
    // BN254 G1 has cofactor one, so its curve check also establishes subgroup membership.
    Some(
        AffineG1::new(read_fq(reader)?, read_fq(reader)?)
            .ok()?
            .into(),
    )
}

fn read_g2(reader: &mut Reader<'_>) -> Option<G2> {
    // Fq2::from_slice uses radix-q encoding, NOT c0||c1. Decode each Fq separately.
    let x = Fq2::new(read_fq(reader)?, read_fq(reader)?);
    let y = Fq2::new(read_fq(reader)?, read_fq(reader)?);
    // AffineG2::new checks the twist equation and the published psi-based subgroup test.
    Some(AffineG2::new(x, y).ok()?.into())
}

fn validate_view(view: &[u8]) -> Option<()> {
    let mut reader = Reader::new(view);
    reader.take(8)?; // Transaction version and locktime.
    let selected = reader.u32()?;
    let inputs = reader.u32()?;
    if selected >= inputs {
        return None;
    }
    for _ in 0..inputs {
        reader.take(48)?; // Outpoint, sequence, and prevout value.
        let script_length = reader.u32()? as usize;
        reader.take(script_length)?;
    }
    let outputs = reader.u32()?;
    for _ in 0..outputs {
        reader.take(8)?; // Output value.
        let script_length = reader.u32()? as usize;
        reader.take(script_length)?;
    }
    reader.is_finished().then_some(())
}

mod heap {
    use core::{
        alloc::{GlobalAlloc, Layout},
        cell::{Cell, UnsafeCell},
        ptr::{addr_of_mut, null_mut},
    };
    use dlmalloc::Dlmalloc;

    const CAPACITY: usize = 256 * 1024;
    #[repr(C, align(4096))]
    struct Storage([u8; CAPACITY]);
    static mut STORAGE: Storage = Storage([0; CAPACITY]);

    struct Arena(Cell<bool>);

    // Supply exactly one static, aligned region. dlmalloc owns all subdivision
    // and reuse; it cannot grow WASM memory or allocate beyond this region.
    unsafe impl dlmalloc::Allocator for Arena {
        fn alloc(&self, size: usize) -> (*mut u8, usize, u32) {
            if size > CAPACITY || self.0.replace(true) {
                return (null_mut(), 0, 0);
            }
            // EXTERN_BIT prevents dlmalloc from releasing this static region.
            (addr_of_mut!(STORAGE).cast::<u8>(), CAPACITY, 1)
        }
        fn remap(&self, _: *mut u8, _: usize, _: usize, _: bool) -> *mut u8 {
            null_mut()
        }
        fn free_part(&self, _: *mut u8, _: usize, _: usize) -> bool {
            false
        }
        fn free(&self, _: *mut u8, _: usize) -> bool {
            false
        }
        fn can_release_part(&self, _: u32) -> bool {
            false
        }
        fn allocates_zeros(&self) -> bool {
            true
        }
        fn page_size(&self) -> usize {
            4096
        }
    }

    struct Allocator(UnsafeCell<Dlmalloc<Arena>>);
    // Like the shared ABI arena, this is only used by a single-threaded fresh
    // WASM instance. The SHA256 host import cannot reenter the guest.
    unsafe impl Sync for Allocator {}
    unsafe impl GlobalAlloc for Allocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            (*self.0.get()).malloc(layout.size(), layout.align())
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            (*self.0.get()).free(pointer, layout.size(), layout.align());
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            (*self.0.get()).calloc(layout.size(), layout.align())
        }
        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            (*self.0.get()).realloc(pointer, layout.size(), layout.align(), size)
        }
    }

    #[global_allocator]
    static ALLOCATOR: Allocator = Allocator(UnsafeCell::new(Dlmalloc::new_with_allocator(Arena(
        Cell::new(false),
    ))));
}
