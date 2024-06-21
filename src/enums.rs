use alloc::string::String;

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
