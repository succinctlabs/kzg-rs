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

fn safe_g1_affine_from_bytes(bytes: Bytes48) -> Result<G1Affine, KzgError> {
    let g1 = G1Affine::from_compressed(&bytes.into());
    if g1.is_none().into() {
        return Err(KzgError::BadArgs(
            "Failed to parse G1Affine from bytes".to_string(),
        ));
    }
    Ok(g1.unwrap())
}

fn safe_scalar_affine_from_bytes(bytes: Bytes32) -> Result<Scalar, KzgError> {
    let lendian: [u8; 32] = Into::<[u8; 32]>::into(bytes)
        .iter()
        .rev()
        .map(|&x| x)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let scalar = Scalar::from_bytes(&lendian);
    if scalar.is_none().into() {
        return Err(KzgError::BadArgs(
            "Failed to parse G1Affine from bytes".to_string(),
        ));
    }
    Ok(scalar.unwrap())
}

pub fn verify_kzg_proof(
    commitment_bytes: Bytes48,
    z_bytes: Bytes32,
    y_bytes: Bytes32,
    proof_bytes: Bytes48,
    kzg_settings: KzgSettings,
) -> bool {
    let z = match safe_scalar_affine_from_bytes(z_bytes) {
        Ok(z) => z,
        Err(_) => {
            return false;
        }
    };
    let y = match safe_scalar_affine_from_bytes(y_bytes) {
        Ok(y) => y,
        Err(_) => {
            return false;
        }
    };
    let commitment = match safe_g1_affine_from_bytes(commitment_bytes) {
        Ok(g1) => g1,
        Err(_) => {
            return false;
        }
    };
    let proof = match safe_g1_affine_from_bytes(proof_bytes) {
        Ok(g1) => g1,
        Err(_) => {
            return false;
        }
    };

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
            let yaml_data = fs::read_to_string(test_file.clone()).unwrap();
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
            assert_eq!(result, test.get_output().unwrap_or_else(|| false));
        }
    }
}
