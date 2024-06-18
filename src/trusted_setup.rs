use bls12_381::{G1Affine, G2Affine, Scalar};

use crate::{
    consts::{BYTES_PER_G1, BYTES_PER_G2, ROOT_OF_UNITY},
    enums::KzgError,
};

const TRUSTED_SETUP: &str = include_str!("trusted_setup.txt");

#[derive(Debug, Default)]
pub struct KzgSettings {
    roots_of_unity: Scalar,
    pub(crate) g1_values: Vec<G1Affine>,
    pub(crate) g2_values: Vec<G2Affine>,
}

pub fn load_trusted_setup_file() -> Result<KzgSettings, KzgError> {
    let trusted_setup_file: Vec<String> = TRUSTED_SETUP
        .to_string()
        .split("\n")
        .map(|x| x.to_string())
        .collect();

    let num_g1_points = trusted_setup_file[0].parse::<usize>().unwrap();
    let num_g2_points = trusted_setup_file[1].parse::<usize>().unwrap();
    let g1_points_idx = num_g1_points + 2;
    let g2_points_idx = g1_points_idx + num_g2_points;

    let g1_points: Vec<[u8; BYTES_PER_G1]> =
        hex::decode(trusted_setup_file[2..g1_points_idx].join(""))
            .unwrap()
            .chunks_exact(BYTES_PER_G1)
            .map(|chunk| {
                let mut array = [0u8; BYTES_PER_G1];
                array.copy_from_slice(chunk);
                array
            })
            .collect();
    let g2_points: Vec<[u8; BYTES_PER_G2]> =
        hex::decode(trusted_setup_file[g1_points_idx..g2_points_idx].join(""))
            .unwrap()
            .chunks_exact(BYTES_PER_G2)
            .map(|chunk| {
                let mut array = [0u8; BYTES_PER_G2];
                array.copy_from_slice(chunk);
                array
            })
            .collect();

    assert_eq!(g1_points.len(), num_g1_points);
    assert_eq!(g2_points.len(), num_g2_points);

    load_trusted_setup(g1_points, g2_points)
}

fn load_trusted_setup(
    g1_points: Vec<[u8; BYTES_PER_G1]>,
    g2_points: Vec<[u8; BYTES_PER_G2]>,
) -> Result<KzgSettings, KzgError> {
    let mut kzg_settings = KzgSettings::default();
    kzg_settings.roots_of_unity = ROOT_OF_UNITY;

    // Convert all bytes to points
    g1_points.iter().for_each(|bytes| {
        let g1_affine =
            G1Affine::from_compressed(bytes).expect("load_trusted_setup Invalid g1 bytes");
        kzg_settings.g1_values.push(g1_affine);
    });
    g2_points.iter().for_each(|bytes| {
        let g2_affine =
            G2Affine::from_compressed(bytes).expect("load_trusted_setup Invalid g2 bytes");
        kzg_settings.g2_values.push(g2_affine);
    });

    let _ = is_trusted_setup_in_lagrange_form(&kzg_settings);

    kzg_settings.roots_of_unity = ROOT_OF_UNITY;
    let bit_reversed_permutation = bit_reversal_permutation(kzg_settings.g1_values)?;
    kzg_settings.g1_values = bit_reversed_permutation;

    Ok(kzg_settings)
}

fn bit_reversal_permutation(g1_values: Vec<G1Affine>) -> Result<Vec<G1Affine>, KzgError> {
    let n = g1_values.len();
    let mut bit_reversed_permutation = vec![G1Affine::default(); n];

    let log_n = (n as f64).log2() as usize;
    for i in 0..n {
        let mut j = 0;
        for k in 0..log_n {
            j |= (i >> k & 1) << (log_n - 1 - k);
        }
        bit_reversed_permutation[j] = g1_values[i];
    }

    Ok(bit_reversed_permutation)
}

fn pairings_verify(a1: G1Affine, a2: G2Affine, b1: G1Affine, b2: G2Affine) -> bool {
    let pairing1 = bls12_381::pairing(&a1, &a2);
    let pairing2 = bls12_381::pairing(&b1, &b2);
    pairing1 == pairing2
}

fn is_trusted_setup_in_lagrange_form(kzg_settings: &KzgSettings) -> Result<(), KzgError> {
    let n1 = kzg_settings.g1_values.len();
    let n2 = kzg_settings.g2_values.len();

    if n1 < 2 || n2 < 2 {
        return Err(KzgError::BadArgs("invalid args".to_string()));
    }

    let a1 = kzg_settings.g1_values[1];
    let a2 = kzg_settings.g2_values[0];
    let b1 = kzg_settings.g1_values[0];
    let b2 = kzg_settings.g2_values[1];

    let is_monomial_form = pairings_verify(a1, a2, b1, b2);
    if !is_monomial_form {
        return Err(KzgError::BadArgs("not in monomial form".to_string()));
    }

    Ok(())
}
