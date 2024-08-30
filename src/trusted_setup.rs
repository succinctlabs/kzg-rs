use crate::{enums::KzgError, NUM_G1_POINTS, NUM_ROOTS_OF_UNITY};

use alloc::sync::Arc;
use bls12_381::{G1Affine, G2Affine, Scalar};
use core::{
    hash::{Hash, Hasher},
    mem::transmute,
    slice,
};
use spin::Once;

pub fn get_roots_of_unity() -> &'static [Scalar] {
    static ROOTS_OF_UNITY: Once<&'static [Scalar]> = Once::new();
    ROOTS_OF_UNITY.call_once(|| {
        let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/roots_of_unity.bin"));
        unsafe { transmute(slice::from_raw_parts(bytes.as_ptr(), NUM_ROOTS_OF_UNITY)) }
    })
}

pub fn get_g1_points() -> &'static [G1Affine] {
    static G1_POINTS: Once<&'static [G1Affine]> = Once::new();
    G1_POINTS.call_once(|| {
        let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/g1.bin"));
        unsafe { transmute(slice::from_raw_parts(bytes.as_ptr(), NUM_G1_POINTS)) }
    })
}

pub fn get_g2_points() -> &'static [G2Affine] {
    static G2_POINTS: Once<&'static [G2Affine]> = Once::new();
    G2_POINTS.call_once(|| {
        let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/g2.bin"));
        unsafe { transmute(slice::from_raw_parts(bytes.as_ptr(), NUM_G1_POINTS)) }
    })
}

pub fn get_kzg_settings() -> KzgSettings {
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
                static DEFAULT: Once<KzgSettings> = Once::new();
                DEFAULT.call_once(|| {
                    KzgSettings::load_trusted_setup_file()
                        .expect("failed to load default trusted setup")
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
