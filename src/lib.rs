use std::error::Error;

use bls12_381::{pairing, G1Affine, G2Affine, Scalar};
use dtypes::*;
use enums::KzgError;
use trusted_setup::KzgSettings;

pub mod consts;
pub mod dtypes;
pub mod enums;
pub mod test_format;
pub mod trusted_setup;

pub fn verify_kzg_proof(
    commitment_bytes: Bytes48,
    z_bytes: Bytes32,
    y_bytes: Bytes32,
    proof_bytes: Bytes48,
    kzg_settings: KzgSettings,
) -> bool {
    let commitment = G1Affine::from_compressed(&commitment_bytes.into()).unwrap();
    let z_lendian: [u8; 32] = Into::<[u8; 32]>::into(z_bytes)
        .iter()
        .rev()
        .map(|&x| x)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let y_lendian: [u8; 32] = Into::<[u8; 32]>::into(y_bytes)
        .iter()
        .rev()
        .map(|&x| x)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let z = Scalar::from_bytes(&z_lendian).unwrap();
    let y = Scalar::from_bytes(&y_lendian).unwrap();
    let proof = G1Affine::from_compressed(&proof_bytes.into()).unwrap();

    let g2_x = G2Affine::generator() * z;
    let x_minus_z = kzg_settings.g2_values[1] - g2_x;

    let g1_y = G1Affine::generator() * y;
    let p_minus_y = commitment - g1_y;

    pairing(&p_minus_y.into(), &G2Affine::generator()) == pairing(&proof, &x_minus_z.into())
}

pub(crate) fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, KzgError> {
    let trimmed_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(trimmed_str)
        .map_err(|e| KzgError::InvalidHexFormat(format!("Failed to decode hex: {}", e)))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use crate::{test_format::Test, trusted_setup};

    const VERIFY_KZG_PROOF_TESTS: &str = "tests/verify_kzg_proof/*/*";

    #[test]
    fn test_verify_kzg_proof() {
        let kzg_settings = trusted_setup::load_trusted_setup_file().unwrap();
        let test_files: Vec<PathBuf> = glob::glob(VERIFY_KZG_PROOF_TESTS)
            .unwrap()
            .map(|x| x.unwrap())
            .collect();
        for test_file in test_files {
            let yaml_data = fs::read_to_string(test_file).unwrap();
            let test: Test = serde_yaml::from_str(&yaml_data).unwrap();
            let (Ok(commitment), Ok(z), Ok(y), Ok(proof)) = (
                test.input.get_commitment(),
                test.input.get_z(),
                test.input.get_y(),
                test.input.get_proof(),
            ) else {
                assert!(test.get_output().is_none());
                continue;
            };

            let result = crate::verify_kzg_proof(commitment, z, y, proof, kzg_settings.clone());
            println!("Result: {} Output: {}", result, test.get_output().unwrap());
        }
    }
}
