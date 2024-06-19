use bls12_381::{G1Affine, G2Affine};

use crate::{
    consts::{BYTES_PER_G1_POINT, BYTES_PER_G2_POINT},
    enums::KzgError,
    hex_to_bytes,
};

const TRUSTED_SETUP: &str = include_str!("trusted_setup.txt");

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct KzgSettings {
    max_width: usize,
    pub(crate) g1_values: Vec<G1Affine>,
    pub(crate) g2_values: Vec<G2Affine>,
}

impl KzgSettings {
    pub fn load_trusted_setup_file() -> Result<Self, KzgError> {
        let trusted_setup_file: Vec<String> = TRUSTED_SETUP
            .to_string()
            .split("\n")
            .map(|x| x.to_string())
            .collect();

        let num_g1_points = trusted_setup_file[0].parse::<usize>().unwrap();
        let num_g2_points = trusted_setup_file[1].parse::<usize>().unwrap();
        let g1_points_idx = num_g1_points + 2;
        let g2_points_idx = g1_points_idx + num_g2_points;

        let g1_points: Vec<[u8; BYTES_PER_G1_POINT]> =
            hex_to_bytes(&trusted_setup_file[2..g1_points_idx].join(""))
                .unwrap()
                .chunks_exact(BYTES_PER_G1_POINT)
                .map(|chunk| {
                    let mut array = [0u8; BYTES_PER_G1_POINT];
                    array.copy_from_slice(chunk);
                    array
                })
                .collect();
        let g2_points: Vec<[u8; BYTES_PER_G2_POINT]> =
            hex_to_bytes(&trusted_setup_file[g1_points_idx..g2_points_idx].join(""))
                .unwrap()
                .chunks_exact(BYTES_PER_G2_POINT)
                .map(|chunk| {
                    let mut array = [0u8; BYTES_PER_G2_POINT];
                    array.copy_from_slice(chunk);
                    array
                })
                .collect();

        assert_eq!(g1_points.len(), num_g1_points);
        assert_eq!(g2_points.len(), num_g2_points);

        Self::load_trusted_setup(g1_points, g2_points)
    }

    pub fn load_trusted_setup(
        g1_points: Vec<[u8; BYTES_PER_G1_POINT]>,
        g2_points: Vec<[u8; BYTES_PER_G2_POINT]>,
    ) -> Result<Self, KzgError> {
        let mut kzg_settings = KzgSettings::default();

        let mut max_scale = 0;
        while (1 << max_scale) < g1_points.len() {
            max_scale += 1;
        }
        kzg_settings.max_width = 1 << max_scale;

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

        let bit_reversed_permutation = bit_reversal_permutation(kzg_settings.g1_values)?;
        kzg_settings.g1_values = bit_reversed_permutation;

        Ok(kzg_settings)
    }
}
fn bit_reversal_permutation(g1_values: Vec<G1Affine>) -> Result<Vec<G1Affine>, KzgError> {
    let n = g1_values.len();
    assert!(n.is_power_of_two(), "n must be a power of 2");

    let mut bit_reversed_permutation: Vec<G1Affine> = vec![G1Affine::default(); n];
    let unused_bit_len = g1_values.len().leading_zeros();

    for i in 0..n {
        let r = i.reverse_bits() >> unused_bit_len + 1;
        bit_reversed_permutation[r] = g1_values[i];
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

#[cfg(test)]
mod tests {
    #[test]
    fn test_bit_reversal_permutation() {
        let N = 16;
        let g1_values: Vec<bls12_381::G1Affine> = (0..N)
            .map(|x| (bls12_381::G1Affine::generator() * bls12_381::Scalar::from(x)).into())
            .collect();

        let bit_reversed_permutation = super::bit_reversal_permutation(g1_values.clone()).unwrap();

        for i in 0..N {
            let r = i.reverse_bits() >> (N.leading_zeros() + 1);
            assert_eq!(bit_reversed_permutation[r as usize], g1_values[i as usize]);
        }
    }
}
