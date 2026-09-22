//! Experimental Groth16/BN254 verification entirely in guest WASM.
//!
//! Fuel limitation: valid proofs exhaust the deployed 100,000,000-unit budget,
//! so this verifier cannot currently authorize spends through ProgramOracle.
//! The default opt-level=s build used roughly 486-488 million units per proof
//! in local fixtures: about 500 million is needed for those cases, not a
//! worst-case bound. Use run.sh --diagnostic-fuel 1000000000 for headroom;
//! diagnostic mode never signs and does not change production limits.
#![no_std]

#[path = "../../../../examples/vault/guest.rs"]
mod guest;

use guest::{Arguments, Reader};
use substrate_bn::{arith::U256, pairing_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Gt, G1, G2};

const DOMAIN: &[u8] = b"sapio/checkzkp/bn254/v1";
const VK_BYTES: usize = 896;
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
    if !program.is_empty() || parameters.len() != VK_BYTES + 32 || witness.len() != PROOF_BYTES + 32
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

    let mut vk = Reader::new(&parameters[..VK_BYTES]);
    let alpha = read_g1(&mut vk)?;
    let beta = read_g2(&mut vk)?;
    let gamma = read_g2(&mut vk)?;
    let delta = read_g2(&mut vk)?;
    let mut ic = read_g1(&mut vk)?;
    // Six public Fr values: the big-endian 128-bit halves of C, T, A.
    for digest in [
        &parameters[VK_BYTES..],
        transaction_digest.as_slice(),
        &witness[PROOF_BYTES..],
    ] {
        for half in digest.as_chunks::<16>().0.iter() {
            let mut scalar = [0u8; 32];
            scalar[16..].copy_from_slice(half);
            // Fr::from_slice reduces; Fr::new instead enforces canonical range.
            let public = Fr::new(U256::from_slice(&scalar).ok()?)?;
            ic = ic + read_g1(&mut vk)? * public;
        }
    }
    if !vk.is_finished() {
        return None;
    }

    // A computed IC accumulator may be zero; encoded points may never be infinity.
    Some(pairing_batch(&[(a, b), (-alpha, beta), (-ic, gamma), (-c, delta)]) == Gt::one())
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
    // AffineG2::new checks the twist equation and ((r-1)P)+P=0, then uses z=1.
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
