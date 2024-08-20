extern crate alloc;

use alloc::string::String;
use core::fmt;

#[derive(Debug, Clone)]
pub enum KzgError {
    /// The supplied data is invalid in some way.
    BadArgs(String),
    /// Internal error - this should never occur.
    InternalError,
    /// The provided bytes are of incorrect length.
    InvalidBytesLength(String),
    /// Error when converting from hex to bytes.
    InvalidHexFormat(String),
    /// The provided trusted setup params are invalid.
    InvalidTrustedSetup(String),
}

impl fmt::Display for KzgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadArgs(s)
            | Self::InvalidBytesLength(s)
            | Self::InvalidHexFormat(s)
            | Self::InvalidTrustedSetup(s) => f.write_str(s),
            Self::InternalError => f.write_str("Internal error"),
        }
    }
}
