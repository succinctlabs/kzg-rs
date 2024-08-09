use crate::dtypes::*;
use crate::enums::KzgError;
use crate::trusted_setup::KzgSettings;

use alloc::{string::ToString, vec::Vec};
use zkvm_pairings::fp::Bls12381;
// use bls12_381::{multi_miller_loop, G1Affine, G2Affine, Gt, MillerLoopResult, Scalar};
use zkvm_pairings::fr::Fr;
use zkvm_pairings::g1::G1Element;
use zkvm_pairings::{g1::G1Affine, g2::G2Affine, pairings::verify_pairing};

fn safe_g1_affine_from_bytes(bytes: &Bytes48) -> Result<G1Affine<Bls12381>, KzgError> {
    let g1 = Bls12381::from_compressed_unchecked(bytes.clone().0.as_ref());
    if g1.is_none().into() {
        return Err(KzgError::BadArgs(
            "Failed to parse G1Affine from bytes".to_string(),
        ));
    }
    Ok(g1.unwrap())
}

fn safe_scalar_affine_from_bytes(bytes: &Bytes32) -> Result<Fr<Bls12381>, KzgError> {
    let lendian: [u8; 32] = Into::<[u8; 32]>::into(bytes.clone())
        .iter()
        .rev()
        .map(|&x| x)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let scalar = Fr::<Bls12381>::from_bytes(&lendian);
    if scalar.is_none().into() {
        return Err(KzgError::BadArgs(
            "Failed to parse G1Affine from bytes".to_string(),
        ));
    }
    Ok(scalar.unwrap())
}

pub struct KzgProof {}

impl KzgProof {
    pub fn verify_kzg_proof(
        commitment_bytes: &Bytes48,
        z_bytes: &Bytes32,
        y_bytes: &Bytes32,
        proof_bytes: &Bytes48,
        kzg_settings: &KzgSettings,
    ) -> Result<bool, KzgError> {
        let z = match safe_scalar_affine_from_bytes(z_bytes) {
            Ok(z) => z,
            Err(e) => {
                return Err(e);
            }
        };
        let y = match safe_scalar_affine_from_bytes(y_bytes) {
            Ok(y) => y,
            Err(e) => {
                return Err(e);
            }
        };
        let commitment = match safe_g1_affine_from_bytes(commitment_bytes) {
            Ok(g1) => g1,
            Err(e) => {
                return Err(e);
            }
        };
        let proof = match safe_g1_affine_from_bytes(proof_bytes) {
            Ok(g1) => g1,
            Err(e) => {
                return Err(e);
            }
        };
        let g2_x = G2Affine::<Bls12381>::generator() * z;
        let x_minus_z = kzg_settings.g2_points[1] - g2_x;

        let g1_y = G1Affine::<Bls12381>::generator() * y;
        let p_minus_y = commitment - g1_y;

        Ok(Self::pairings_verify(
            &p_minus_y,
            &G2Affine::generator(),
            &proof,
            &x_minus_z,
        ))
    }

    fn pairings_verify(
        a1: &G1Affine<Bls12381>,
        a2: &G2Affine<Bls12381>,
        b1: &G1Affine<Bls12381>,
        b2: &G2Affine<Bls12381>,
    ) -> bool {
        verify_pairing(&[-*a1, *b1], &[*a2, *b2])
    }
}

#[cfg(all(feature = "std", feature = "cache"))]
#[cfg(test)]
mod tests {
    use super::*;
    use serde_derive::Deserialize;
    use std::{fs, path::PathBuf};

    const VERIFY_KZG_PROOF_TESTS: &str = "tests/verify_kzg_proof/*/*";

    #[derive(Deserialize)]
    pub struct Input<'a> {
        commitment: &'a str,
        z: &'a str,
        y: &'a str,
        proof: &'a str,
    }

    impl Input<'_> {
        pub fn get_commitment(&self) -> Result<Bytes48, KzgError> {
            Bytes48::from_hex(self.commitment)
        }

        pub fn get_z(&self) -> Result<Bytes32, KzgError> {
            Bytes32::from_hex(self.z)
        }

        pub fn get_y(&self) -> Result<Bytes32, KzgError> {
            Bytes32::from_hex(self.y)
        }

        pub fn get_proof(&self) -> Result<Bytes48, KzgError> {
            Bytes48::from_hex(self.proof)
        }
    }

    #[derive(Deserialize)]
    pub struct Test<'a> {
        #[serde(borrow)]
        pub input: Input<'a>,
        output: Option<bool>,
    }

    impl Test<'_> {
        pub fn get_output(&self) -> Option<bool> {
            self.output
        }
    }

    #[test]
    fn test_verify_kzg_proof() {
        let kzg_settings = KzgSettings::load_trusted_setup_file().unwrap();
        let test_files: Vec<PathBuf> = glob::glob(VERIFY_KZG_PROOF_TESTS)
            .unwrap()
            .map(|x| x.unwrap())
            .collect();
        for test_file in test_files {
            println!("Test file: {:?}", test_file);
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

            let result = KzgProof::verify_kzg_proof(&commitment, &z, &y, &proof, &kzg_settings);
            match result {
                Ok(result) => {
                    assert_eq!(result, test.get_output().unwrap_or_else(|| false));
                }
                Err(e) => {
                    assert!(test.get_output().is_none());
                    // eprintln!("Error: {:?}", e);
                }
            }
        }
    }
}
