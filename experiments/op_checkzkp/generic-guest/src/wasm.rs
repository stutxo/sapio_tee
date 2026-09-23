use crate::{verify, MAX_ARGUMENT_BYTES};
use core::ptr::{addr_of, addr_of_mut};

const INPUT_CAPACITY: usize = 3 * MAX_ARGUMENT_BYTES;
static mut INPUT: [u8; INPUT_CAPACITY] = [0; INPUT_CAPACITY];
static mut INPUT_USED: usize = 0;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

/// Allocate disjoint host-written arguments in a fresh instance's fixed arena.
/// Zero means allocation failed; each nonempty argument is at most 65,536 bytes.
#[no_mangle]
pub extern "C" fn groth16_alloc_v1(length: u32) -> u32 {
    if length as usize > MAX_ARGUMENT_BYTES {
        return 0;
    }
    // The instance is single-threaded and has no imports that could reenter it.
    unsafe {
        let used = INPUT_USED;
        let Some(end) = used.checked_add(length as usize) else {
            return 0;
        };
        if end > INPUT_CAPACITY {
            return 0;
        }
        INPUT_USED = end;
        addr_of_mut!(INPUT).cast::<u8>().add(used) as u32
    }
}

/// Return 1 for a valid proof, 0 for a false equation, -1 for malformed input or
/// a verifier error. Traps (including exhausted fuel) are not rejection results.
#[no_mangle]
pub extern "C" fn groth16_verify_v1(
    vk_pointer: u32,
    vk_length: u32,
    proof_pointer: u32,
    proof_length: u32,
    inputs_pointer: u32,
    inputs_length: u32,
) -> i32 {
    if [vk_length, proof_length, inputs_length]
        .iter()
        .any(|length| *length as usize > MAX_ARGUMENT_BYTES)
    {
        return -1;
    }
    let Some(verifying_key) = input_slice(vk_pointer, vk_length) else {
        return -1;
    };
    let Some(proof) = input_slice(proof_pointer, proof_length) else {
        return -1;
    };
    let Some(public_inputs) = input_slice(inputs_pointer, inputs_length) else {
        return -1;
    };
    match verify(verifying_key, proof, public_inputs) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}

fn input_slice(pointer: u32, length: u32) -> Option<&'static [u8]> {
    if length == 0 {
        return Some(&[]);
    }
    let pointer = pointer as usize;
    let start = addr_of!(INPUT).cast::<u8>() as usize;
    let offset = pointer.checked_sub(start)?;
    let end = offset.checked_add(length as usize)?;
    // Like the vault ABI, only the bounded, already allocated input arena may
    // be read. Empty arguments deliberately ignore their pointer value.
    unsafe {
        if end > INPUT_USED {
            return None;
        }
        Some(core::slice::from_raw_parts(
            pointer as *const u8,
            length as usize,
        ))
    }
}

mod heap {
    use core::{
        alloc::{GlobalAlloc, Layout},
        cell::{Cell, UnsafeCell},
        ptr::{addr_of_mut, null_mut},
    };
    use dlmalloc::Dlmalloc;

    // Bounded space for validated keys (including upstream preparation's clone),
    // scalars and pairing temporaries. Together with the 192-KiB input arena and
    // the build's 1-MiB stack, this fits in the 8-MiB initial memory. It does not
    // request memory growth; the module's maximum memory remains 64 MiB.
    const CAPACITY: usize = 4 * 1024 * 1024;
    #[repr(C, align(4096))]
    struct Storage([u8; CAPACITY]);
    static mut STORAGE: Storage = Storage([0; CAPACITY]);

    struct Arena(Cell<bool>);

    // Supply one static aligned region; dlmalloc owns all subdivision and reuse.
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
    // The same single-threaded, nonreentrant instance invariant as the input ABI.
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
