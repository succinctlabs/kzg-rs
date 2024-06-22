use core::{
    hash::{Hash, Hasher},
    mem::transmute,
    slice,
};

use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use bls12_381::{G1Affine, G2Affine};
use once_cell::race::OnceBox;

use crate::{
    consts::{BYTES_PER_G1_POINT, BYTES_PER_G2_POINT},
    enums::KzgError,
    hex_to_bytes, NUM_G1_POINTS, NUM_G2_POINTS,
};

const TRUSTED_SETUP_FILE: &str = include_str!("trusted_setup.txt");

#[cfg(feature = "cache")]
pub const fn get_g1_points() -> &'static [G1Affine] {
    const G1_BYTES: &[u8] = include_bytes!("g1.bin");
    let g1: &[G1Affine] =
        unsafe { transmute(slice::from_raw_parts(G1_BYTES.as_ptr(), NUM_G1_POINTS)) };
    g1
}

#[cfg(feature = "cache")]
pub const fn get_g2_points() -> &'static [G2Affine] {
    const G2_BYTES: &[u8] = include_bytes!("g2.bin");
    let g2: &[G2Affine] =
        unsafe { transmute(slice::from_raw_parts(G2_BYTES.as_ptr(), NUM_G1_POINTS)) };
    g2
}

#[cfg(feature = "cache")]
pub const fn get_kzg_settings() -> KzgSettings {
    KzgSettings {
        max_width: 16,
        g1_points: get_g1_points(),
        g2_points: get_g2_points(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KzgSettings {
    pub(crate) max_width: usize,
    pub(crate) g1_points: &'static [G1Affine],
    pub(crate) g2_points: &'static [G2Affine],
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

#[cfg(feature = "cache")]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KzgSettingsOwned {
    pub max_width: usize,
    pub g1_points: [G1Affine; NUM_G1_POINTS],
    pub g2_points: [G2Affine; NUM_G2_POINTS],
}

impl KzgSettings {
    #[cfg(feature = "cache")]
    pub fn load_trusted_setup_file() -> Result<Self, KzgError> {
        Ok(get_kzg_settings())
    }
}

pub fn load_trusted_setup_file_brute() -> Result<KzgSettingsOwned, KzgError> {
    let trusted_setup_file: Vec<String> = TRUSTED_SETUP_FILE
        .to_string()
        .split("\n")
        .map(|x| x.to_string())
        .collect();

    let num_g1_points = trusted_setup_file[0].parse::<usize>().unwrap();
    let num_g2_points = trusted_setup_file[1].parse::<usize>().unwrap();
    let g1_points_idx = num_g1_points + 2;
    let g2_points_idx = g1_points_idx + num_g2_points;

    let _g1_points: Vec<[u8; BYTES_PER_G1_POINT]> =
        hex_to_bytes(&trusted_setup_file[2..g1_points_idx].join(""))
            .unwrap()
            .chunks_exact(BYTES_PER_G1_POINT)
            .map(|chunk| {
                let mut array = [0u8; BYTES_PER_G1_POINT];
                array.copy_from_slice(chunk);
                array
            })
            .collect();
    let _g2_points: Vec<[u8; BYTES_PER_G2_POINT]> =
        hex_to_bytes(&trusted_setup_file[g1_points_idx..g2_points_idx].join(""))
            .unwrap()
            .chunks_exact(BYTES_PER_G2_POINT)
            .map(|chunk| {
                let mut array = [0u8; BYTES_PER_G2_POINT];
                array.copy_from_slice(chunk);
                array
            })
            .collect();

    assert_eq!(_g1_points.len(), num_g1_points);
    assert_eq!(_g2_points.len(), num_g2_points);

    let mut max_scale = 0;
    while (1 << max_scale) < _g1_points.len() {
        max_scale += 1;
    }
    let max_width = 1 << max_scale;

    let mut g1_points: [G1Affine; NUM_G1_POINTS] = [G1Affine::identity(); NUM_G1_POINTS];
    let mut g2_points: [G2Affine; NUM_G2_POINTS] = [G2Affine::identity(); NUM_G2_POINTS];

    _g1_points.iter().enumerate().for_each(|(i, bytes)| {
        g1_points[i] = G1Affine::from_compressed_unchecked(bytes)
            .expect("load_trusted_setup Invalid g1 bytes");
    });

    _g2_points.iter().enumerate().for_each(|(i, bytes)| {
        g2_points[i] = G2Affine::from_compressed_unchecked(bytes)
            .expect("load_trusted_setup Invalid g2 bytes");
    });

    let _ = is_trusted_setup_in_lagrange_form(&g1_points, &g2_points);

    let bit_reversed_permutation = bit_reversal_permutation(&g1_points)?;
    let g1_points = bit_reversed_permutation;

    Ok(KzgSettingsOwned {
        max_width,
        g1_points,
        g2_points,
    })
}

fn bit_reversal_permutation(g1_points: &[G1Affine]) -> Result<[G1Affine; NUM_G1_POINTS], KzgError> {
    let n = g1_points.len();
    assert!(n.is_power_of_two(), "n must be a power of 2");

    let mut bit_reversed_permutation: [G1Affine; NUM_G1_POINTS] =
        [G1Affine::identity(); NUM_G1_POINTS];
    let unused_bit_len = g1_points.len().leading_zeros();

    for i in 0..n {
        let r = i.reverse_bits() >> unused_bit_len + 1;
        bit_reversed_permutation[r] = g1_points[i];
    }

    Ok(bit_reversed_permutation)
}

fn pairings_verify(a1: G1Affine, a2: G2Affine, b1: G1Affine, b2: G2Affine) -> bool {
    let pairing1 = bls12_381::pairing(&a1, &a2);
    let pairing2 = bls12_381::pairing(&b1, &b2);
    pairing1 == pairing2
}

fn is_trusted_setup_in_lagrange_form(
    g1_points: &[G1Affine],
    g2_points: &[G2Affine],
) -> Result<(), KzgError> {
    let n1 = g1_points.len();
    let n2 = g2_points.len();

    if n1 < 2 || n2 < 2 {
        return Err(KzgError::BadArgs("invalid args".to_string()));
    }

    let a1 = g1_points[1];
    let a2 = g2_points[0];
    let b1 = g1_points[0];
    let b2 = g2_points[1];

    let is_monomial_form = pairings_verify(a1, a2, b1, b2);
    if !is_monomial_form {
        return Err(KzgError::BadArgs("not in monomial form".to_string()));
    }

    Ok(())
}
