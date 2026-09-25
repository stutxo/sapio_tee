#![cfg_attr(all(target_arch = "wasm32", feature = "browser-abi"), no_std)]

//! Two-key BIP327 recovery signatures for a Taproot CHECKSIG leaf.
//! The aggregate key is not TapTweaked: it is the key inside the leaf.

use secp256k1::musig::{new_nonce_pair, AggregatedNonce, KeyAggCache, Session, SessionSecretRand};
use secp256k1::{Keypair, PublicKey, Scalar, SecretKey, XOnlyPublicKey};

// Best-effort erasure only: Rust and the underlying library may copy secrets.
struct EraseSecret(SecretKey);

impl Drop for EraseSecret {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

struct EraseKeypair(Keypair);

impl Drop for EraseKeypair {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

/// Derive a compressed SEC1 public key; reject zero/out-of-range scalars.
pub fn public_key(secret: &[u8; 32]) -> Option<[u8; 33]> {
    let secret = EraseSecret(SecretKey::from_secret_bytes(*secret).ok()?);
    Some(PublicKey::from_secret_key(&secret.0).serialize())
}

fn canonical_keys(keys: &[[u8; 33]; 2]) -> Option<[PublicKey; 2]> {
    // Negations of the same point are not two independent recovery keys.
    if keys[0][1..] == keys[1][1..] {
        return None;
    }
    let ordered = if keys[0] < keys[1] {
        [&keys[0], &keys[1]]
    } else {
        [&keys[1], &keys[0]]
    };
    Some([
        PublicKey::from_byte_array_compressed(*ordered[0]).ok()?,
        PublicKey::from_byte_array_compressed(*ordered[1]).ok()?,
    ])
}

/// BIP327 aggregation, sorted by the complete compressed public-key bytes.
pub fn aggregate_keys(keys: &[[u8; 33]; 2]) -> Option<[u8; 32]> {
    let keys = canonical_keys(keys)?;
    let cache = KeyAggCache::new(&[&keys[0], &keys[1]]);
    Some(cache.agg_pk().to_byte_array())
}

/// Produce and verify both MuSig2 partials, then verify the final BIP340 signature.
///
/// Both private keys must match the expected pair, in either order. Each caller
/// must supply fresh, independent CSPRNG randomness for each participant on
/// EVERY invocation, including retries. Nonces are never exported or persisted.
/// Zero or identical randomness is rejected, but freshness across calls cannot
/// be established by this deliberately stateless API.
pub fn sign(
    keys: &[[u8; 32]; 2],
    expected: &[[u8; 33]; 2],
    message: &[u8; 32],
    randomness: &[[u8; 32]; 2],
) -> Option<[u8; 64]> {
    let expected = canonical_keys(expected)?;
    if randomness[0] == randomness[1]
        || randomness
            .iter()
            .any(|bytes| bytes.iter().all(|byte| *byte == 0))
    {
        return None;
    }
    let secret0 = EraseSecret(SecretKey::from_secret_bytes(keys[0]).ok()?);
    let secret1 = EraseSecret(SecretKey::from_secret_bytes(keys[1]).ok()?);
    let public0 = PublicKey::from_secret_key(&secret0.0);
    let public1 = PublicKey::from_secret_key(&secret1.0);
    if !((public0 == expected[0] && public1 == expected[1])
        || (public0 == expected[1] && public1 == expected[0]))
    {
        return None;
    }
    let cache = KeyAggCache::new(&[&expected[0], &expected[1]]);
    let keypair0 = EraseKeypair(Keypair::from_secret_key(&secret0.0));
    let keypair1 = EraseKeypair(Keypair::from_secret_key(&secret1.0));

    // Passing Some(secret) makes libsecp256k1's BIP327 NonceGen mix the
    // randomness with the private key, binding both nonces to this signer,
    // the aggregate key and the message. Nonzero randomness was checked above.
    let (nonce0, public_nonce0) = new_nonce_pair(
        SessionSecretRand::assume_uniformly_random(randomness[0]),
        Some(&cache),
        Some(secret0.0),
        public0,
        Some(message),
        None,
    );
    let (nonce1, public_nonce1) = new_nonce_pair(
        SessionSecretRand::assume_uniformly_random(randomness[1]),
        Some(&cache),
        Some(secret1.0),
        public1,
        Some(message),
        None,
    );
    let aggregate_nonce = AggregatedNonce::new(&[&public_nonce0, &public_nonce1]);
    let session = Session::new(&cache, aggregate_nonce, message);

    // partial_sign consumes each non-Copy secret nonce and clears it in C.
    // Generate both partials before any fallible return so neither nonce is
    // left unused in the ordinary invalid-signature path.
    let partial0 = session.partial_sign(nonce0, &keypair0.0, &cache);
    let partial1 = session.partial_sign(nonce1, &keypair1.0, &cache);
    let valid0 = session.partial_verify(&cache, &partial0, &public_nonce0, public0);
    let valid1 = session.partial_verify(&cache, &partial1, &public_nonce1, public1);
    if !valid0 || !valid1 {
        return None;
    }
    let signature = session.partial_sig_agg(&[&partial0, &partial1]);
    Some(
        signature
            .verify(&cache.agg_pk(), message)
            .ok()?
            .to_byte_array(),
    )
}

/// Add a caller-computed TapTweak to the separate internal key, not the leaf key.
pub fn tweak_output(internal_key: &[u8; 32], tweak: &[u8; 32]) -> Option<([u8; 32], u8)> {
    let internal_key = XOnlyPublicKey::from_byte_array(*internal_key).ok()?;
    let tweak = Scalar::from_be_bytes(*tweak).ok()?;
    let (output, parity) = internal_key.add_tweak(&tweak).ok()?;
    Some((output.to_byte_array(), parity.to_u8()))
}

// The native rlib neither replaces its caller's allocator nor installs a panic
// handler. The browser creates one fresh WASM instance per operation.
#[cfg(all(target_arch = "wasm32", feature = "browser-abi"))]
mod wasm {
    use core::alloc::{GlobalAlloc, Layout};
    use core::ptr::{addr_of, addr_of_mut, null_mut};

    const INPUT_CAPACITY: usize = 226;
    const OUTPUT_CAPACITY: usize = 64;
    const HEAP_CAPACITY: usize = 65_536;
    static mut INPUT: [u8; INPUT_CAPACITY] = [0; INPUT_CAPACITY];
    static mut OUTPUT: [u8; OUTPUT_CAPACITY] = [0; OUTPUT_CAPACITY];

    // The cryptographic path uses fixed-size arrays, but secp256k1's alloc
    // feature still requires an allocator. Bound any library scratch space.
    #[repr(C, align(16))]
    struct Heap([u8; HEAP_CAPACITY]);
    static mut HEAP: Heap = Heap([0; HEAP_CAPACITY]);
    static mut HEAP_USED: usize = 0;
    struct Arena;

    #[global_allocator]
    static ALLOCATOR: Arena = Arena;

    unsafe impl GlobalAlloc for Arena {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let base = addr_of_mut!(HEAP).cast::<u8>() as usize;
            let Some(start) = base
                .checked_add(HEAP_USED)
                .and_then(|address| address.checked_add(layout.align() - 1))
                .map(|address| address & !(layout.align() - 1))
            else {
                return null_mut();
            };
            let Some(end) = start
                .checked_sub(base)
                .and_then(|offset| offset.checked_add(layout.size()))
            else {
                return null_mut();
            };
            if end > HEAP_CAPACITY {
                return null_mut();
            }
            HEAP_USED = end;
            start as *mut u8
        }

        unsafe fn dealloc(&self, _: *mut u8, _: Layout) {
            // The entire instance is wiped and discarded after the operation.
        }
    }

    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
        core::arch::wasm32::unreachable()
    }

    #[no_mangle]
    pub extern "C" fn recovery_input() -> u32 {
        addr_of_mut!(INPUT).cast::<u8>() as u32
    }

    #[no_mangle]
    pub extern "C" fn recovery_output() -> u32 {
        addr_of_mut!(OUTPUT).cast::<u8>() as u32
    }

    #[no_mangle]
    pub extern "C" fn recovery_input_capacity() -> u32 {
        INPUT_CAPACITY as u32
    }

    #[no_mangle]
    pub extern "C" fn recovery_output_capacity() -> u32 {
        OUTPUT_CAPACITY as u32
    }

    fn pair<const N: usize>(bytes: &[u8]) -> Option<&[[u8; N]; 2]> {
        let (chunks, remainder) = bytes.as_chunks::<N>();
        if !remainder.is_empty() {
            return None;
        }
        chunks.try_into().ok()
    }

    fn execute(operation: u32, input: &[u8], output: &mut [u8; OUTPUT_CAPACITY]) -> Option<usize> {
        match (operation, input.len()) {
            (1, 32) => {
                output[..33].copy_from_slice(&super::public_key(input.try_into().ok()?)?);
                Some(33)
            }
            (2, 66) => {
                output[..32].copy_from_slice(&super::aggregate_keys(pair(input)?)?);
                Some(32)
            }
            (3, INPUT_CAPACITY) => {
                *output = super::sign(
                    pair(&input[..64])?,
                    pair(&input[64..130])?,
                    input[130..162].try_into().ok()?,
                    pair(&input[162..])?,
                )?;
                Some(64)
            }
            (4, 64) => {
                let (key, parity) = super::tweak_output(
                    input[..32].try_into().ok()?,
                    input[32..].try_into().ok()?,
                )?;
                output[..32].copy_from_slice(&key);
                output[32] = parity;
                Some(33)
            }
            _ => None,
        }
    }

    /// Fixed input arena ABI: 1=secret32, 2=pubkeys66,
    /// 3=secrets64||pubkeys66||message32||randomness64, 4=internal32||tweak32.
    /// Returns the public output length, or zero for any invalid input. No
    /// caller-provided pointer is dereferenced. There are no host imports.
    #[no_mangle]
    pub extern "C" fn recovery_execute(operation: u32, input_length: u32) -> u32 {
        unsafe {
            let output = &mut *addr_of_mut!(OUTPUT);
            output.fill(0);
            let length = if input_length as usize <= INPUT_CAPACITY {
                let input = &*addr_of!(INPUT);
                execute(operation, &input[..input_length as usize], output).unwrap_or(0)
            } else {
                0
            };
            // Volatile writes make this best-effort input erasure observable.
            // JS also wipes ALL linear memory, including stack/library copies.
            for i in 0..INPUT_CAPACITY {
                addr_of_mut!(INPUT).cast::<u8>().add(i).write_volatile(0);
            }
            length as u32
        }
    }
}
