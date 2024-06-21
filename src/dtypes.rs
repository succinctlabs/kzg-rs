use crate::enums::KzgError;
use crate::hex_to_bytes;

use alloc::string::ToString;

macro_rules! define_bytes_type {
    ($name:ident, $size:expr) => {
        #[derive(Debug, Clone)]
        pub struct $name([u8; $size]);

        impl $name {
            pub fn from_slice(slice: &[u8]) -> Result<Self, KzgError> {
                if slice.len() != $size {
                    return Err(KzgError::InvalidBytesLength(
                        "Invalid slice length".to_string(),
                    ));
                }
                let mut bytes = [0u8; $size];
                bytes.copy_from_slice(slice);
                Ok($name(bytes))
            }

            pub fn from_hex(hex_str: &str) -> Result<Self, KzgError> {
                Self::from_slice(&hex_to_bytes(hex_str).unwrap())
            }
        }

        impl Into<[u8; $size]> for $name {
            fn into(self) -> [u8; $size] {
                self.0
            }
        }
    };
}

define_bytes_type!(Bytes32, 32);
define_bytes_type!(Bytes48, 48);

#[cfg(test)]
mod tests {
    #[test]
    fn test_bytes32() {
        let bytes = crate::dtypes::Bytes32::from_slice(&[0u8; 32]).unwrap();
        assert_eq!(bytes.0.len(), 32);
    }

    #[test]
    fn test_bytes48() {
        let bytes = crate::dtypes::Bytes48::from_slice(&[0u8; 48]).unwrap();
        assert_eq!(bytes.0.len(), 48);
    }
}
