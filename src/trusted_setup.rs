use core::{
    hash::{Hash, Hasher},
    mem::transmute,
    slice,
};
use alloc::{boxed::Box, sync::Arc};
use bls12_381::{G1Affine, G2Affine, Scalar};
use once_cell::race::OnceBox;

use crate::{enums::KzgError, NUM_G1_POINTS, NUM_ROOTS_OF_UNITY};

pub const fn get_roots_of_unity() -> &'static [Scalar] {
    const ROOT_OF_UNITY_BYTES: &[u8] = include_bytes!("roots_of_unity.bin");
    let roots_of_unity: &[Scalar] = unsafe {
        transmute(slice::from_raw_parts(
            ROOT_OF_UNITY_BYTES.as_ptr(),
            NUM_ROOTS_OF_UNITY,
        ))
    };
    roots_of_unity
}

pub const fn get_g1_points() -> &'static [G1Affine] {
    const G1_BYTES: &[u8] = include_bytes!("g1.bin");
    let g1: &[G1Affine] =
        unsafe { transmute(slice::from_raw_parts(G1_BYTES.as_ptr(), NUM_G1_POINTS)) };
    g1
}

pub const fn get_g2_points() -> &'static [G2Affine] {
    const G2_BYTES: &[u8] = include_bytes!("g2.bin");
    let g2: &[G2Affine] =
        unsafe { transmute(slice::from_raw_parts(G2_BYTES.as_ptr(), NUM_G1_POINTS)) };
    g2
}

pub const fn get_kzg_settings() -> KzgSettings {
    KzgSettings {
        roots_of_unity: get_roots_of_unity(),
        g1_points: get_g1_points(),
        g2_points: get_g2_points(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C, align(4))]
pub struct KzgSettings {
    pub roots_of_unity: &'static [Scalar],
    pub g1_points: &'static [G1Affine],
    pub g2_points: &'static [G2Affine],
}

#[derive(Debug, Clone, Default, Eq)]
pub enum EnvKzgSettings {
    #[default]
    Default,
    Custom(Arc<KzgSettings>),
}

impl PartialEq for EnvKzgSettings {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Default, Self::Default) => true,
            (Self::Custom(a), Self::Custom(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

impl Hash for EnvKzgSettings {
    fn hash<H: Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            Self::Default => {}
            Self::Custom(settings) => Arc::as_ptr(settings).hash(state),
        }
    }
}

impl EnvKzgSettings {
    pub fn get(&self) -> &KzgSettings {
        match self {
            Self::Default => {
                static DEFAULT: OnceBox<KzgSettings> = OnceBox::new();
                DEFAULT.get_or_init(|| {
                    let settings = KzgSettings::load_trusted_setup_file()
                        .expect("failed to load default trusted setup");
                    Box::new(settings)
                })
            }
            Self::Custom(settings) => settings,
        }
    }
}

impl KzgSettings {
    pub fn load_trusted_setup_file() -> Result<Self, KzgError> {
        Ok(get_kzg_settings())
    }
}
