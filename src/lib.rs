// #![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod consts;
pub mod dtypes;
pub mod enums;
pub mod kzg_proof;
pub mod trusted_setup;

use alloc::vec::Vec;
use bls12_381::{G1Affine, G2Affine};
pub use consts::*;
pub use dtypes::*;
pub use kzg_proof::KzgProof;
pub use trusted_setup::*;

pub use enums::KzgError;

pub(crate) fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, KzgError> {
    let trimmed_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(trimmed_str)
        .map_err(|e| KzgError::InvalidHexFormat(format!("Failed to decode hex: {}", e)))
}

pub(crate) fn pairings_verify(a1: G1Affine, a2: G2Affine, b1: G1Affine, b2: G2Affine) -> bool {
    let pairing1 = bls12_381::pairing(&a1, &a2);
    let pairing2 = bls12_381::pairing(&b1, &b2);
    pairing1 == pairing2
}
