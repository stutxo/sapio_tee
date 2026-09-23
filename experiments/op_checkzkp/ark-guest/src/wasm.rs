use crate::{
    codec::{read_g1, read_g2, read_prepared, read_scalar_half},
    guest::{self, Arguments, Reader},
    PREPARED_PARAMETERS_BYTES,
};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof};

#[cfg(feature = "msm")]
use ark_bn254::G1Projective;
#[cfg(feature = "msm")]
use ark_ec::{AffineRepr, VariableBaseMSM};

const DOMAIN: &[u8] = b"sapio/checkzkp/bn254/v1";
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
        || parameters.len() != PREPARED_PARAMETERS_BYTES
        || parameters.get(..4)? != b"G16A"
        || witness.len() != PROOF_BYTES + 32
    {
        return None;
    }
    validate_view(view)?;
    let mut proof_reader = Reader::new(&witness[..PROOF_BYTES]);
    let proof = Proof::<Bn254> {
        a: read_g1(&mut proof_reader)?,
        b: read_g2(&mut proof_reader)?,
        c: read_g1(&mut proof_reader)?,
    };
    if !proof_reader.is_finished() {
        return None;
    }

    let mut transcript = [0u8; DOMAIN.len() + 32];
    transcript[..DOMAIN.len()].copy_from_slice(DOMAIN);
    guest::hash(view, &mut transcript[DOMAIN.len()..])?;
    let mut transaction_digest = [0u8; 32];
    guest::hash(&transcript, &mut transaction_digest)?;

    let prepared = read_prepared(&mut Reader::new(&parameters[4..]))?;
    // Four dynamic Fr values: the big-endian 128-bit halves of T and A. C's
    // halves were folded into IC0 by the validated native preparation.
    let public_inputs: [Fr; 4] = [
        read_scalar_half(&transaction_digest[..16])?,
        read_scalar_half(&transaction_digest[16..])?,
        read_scalar_half(&witness[PROOF_BYTES..PROOF_BYTES + 16])?,
        read_scalar_half(&witness[PROOF_BYTES + 16..])?,
    ];

    #[cfg(not(feature = "msm"))]
    let verified = Groth16::<Bn254>::verify_proof(&prepared, &proof, &public_inputs);
    #[cfg(feature = "msm")]
    let verified = {
        let ic = prepared.vk.gamma_abc_g1[0].into_group()
            + G1Projective::msm(&prepared.vk.gamma_abc_g1[1..], &public_inputs).ok()?;
        Groth16::<Bn254>::verify_proof_with_prepared_inputs(&prepared, &proof, &ic)
    };
    // In particular, a malformed committed line table producing a zero Miller
    // result is an UnexpectedIdentity error from final exponentiation, not a
    // panic. All tables have exactly the coefficient count its loop consumes.
    verified.ok()
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
