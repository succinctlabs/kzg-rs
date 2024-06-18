macro_rules! define_bytes_type {
    ($name:ident, $size:expr) => {
        pub struct $name([u8; $size]);

        impl $name {
            pub fn from_slice(slice: &[u8]) -> Self {
                let mut bytes = [0u8; $size];
                bytes.copy_from_slice(slice);
                $name(bytes)
            }
        }
    };
}

define_bytes_type!(Bytes32, 32);
define_bytes_type!(Bytes48, 48);
