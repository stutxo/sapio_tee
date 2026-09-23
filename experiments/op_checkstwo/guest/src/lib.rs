//! Experimental STWO arithmetic verification under the unchanged guest limits.
//! Public recurrence only: no credential, authorization, or privacy claim.
#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

#[cfg(target_arch = "wasm32")]
#[path = "../../../../examples/vault/guest.rs"]
mod guest;

#[cfg(target_arch = "wasm32")]
mod wasm;
