use crate::guest::{self, Arguments, Reader};

use checkstwo_verifier::DOMAIN;

// Generated from the fixed selector trace before the guest build. A missing
// root is a build error, never a witness-selected root or a placeholder.
const PREPROCESSED_ROOT: &[u8; 32] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/preprocessed-root.bin"
));

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
    if !program.is_empty() {
        return None;
    }
    validate_view(view)?;
    let mut transcript = [0u8; DOMAIN.len() + 32];
    transcript[..DOMAIN.len()].copy_from_slice(DOMAIN);
    guest::hash(view, &mut transcript[DOMAIN.len()..])?;
    let mut transaction = [0u8; 32];
    guest::hash(&transcript, &mut transaction)?;
    Some(
        checkstwo_verifier::verify_bytes(parameters, &transaction, witness, *PREPROCESSED_ROOT)
            .is_ok(),
    )
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

    struct Allocator {
        arena: UnsafeCell<Dlmalloc<Arena>>,
        live: Cell<usize>,
        peak: Cell<usize>,
    }

    impl Allocator {
        fn account(&self, old: usize, new: usize) {
            let live = self.live.get() - old + new;
            self.live.set(live);
            self.peak.set(self.peak.get().max(live));
        }
    }
    // Like the shared ABI arena, this is only used by a single-threaded fresh
    // WASM instance. The SHA256 host import cannot reenter the guest.
    unsafe impl Sync for Allocator {}
    unsafe impl GlobalAlloc for Allocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let pointer = (*self.arena.get()).malloc(layout.size(), layout.align());
            if !pointer.is_null() {
                self.account(0, layout.size());
            }
            pointer
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            (*self.arena.get()).free(pointer, layout.size(), layout.align());
            self.account(layout.size(), 0);
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            let pointer = (*self.arena.get()).calloc(layout.size(), layout.align());
            if !pointer.is_null() {
                self.account(0, layout.size());
            }
            pointer
        }
        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            let replacement =
                (*self.arena.get()).realloc(pointer, layout.size(), layout.align(), size);
            if !replacement.is_null() {
                self.account(layout.size(), size);
            }
            replacement
        }
    }

    #[global_allocator]
    static ALLOCATOR: Allocator = Allocator {
        arena: UnsafeCell::new(Dlmalloc::new_with_allocator(Arena(Cell::new(false)))),
        live: Cell::new(0),
        peak: Cell::new(0),
    };

    /// Peak live requested allocation bytes, excluding dlmalloc metadata and
    /// fragmentation. The backing arena remains exactly 256 KiB.
    #[no_mangle]
    pub extern "C" fn checkstwo_heap_peak_requested_bytes() -> u32 {
        ALLOCATOR.peak.get() as u32
    }
}
