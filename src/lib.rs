#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

pub mod consts;
pub mod dtypes;
pub mod enums;
pub mod kzg_proof;
pub mod test_format;
pub mod trusted_setup;

pub use consts::*;
pub use dtypes::*;
pub use kzg_proof::KzgProof;
pub use trusted_setup::*;

use enums::KzgError;

pub(crate) fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, KzgError> {
    let trimmed_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(trimmed_str)
        .map_err(|e| KzgError::InvalidHexFormat(format!("Failed to decode hex: {}", e)))
}
