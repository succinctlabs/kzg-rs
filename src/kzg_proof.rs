use crate::dtypes::*;
use crate::enums::KzgError;
use crate::trusted_setup::KzgSettings;
use alloc::vec::Vec;
use bls12_381::{pairing, G1Affine, G2Affine, Scalar};

// #[sp1_derive::cycle_tracker]
fn safe_g1_affine_from_bytes(bytes: &Bytes48) -> Result<G1Affine, KzgError> {
    let g1 = G1Affine::from_compressed(&(bytes.clone().into()));
    if g1.is_none().into() {
        return Err(KzgError::BadArgs(
            "Failed to parse G1Affine from bytes".to_string(),
        ));
    }
    Ok(g1.unwrap())
}

// #[sp1_derive::cycle_tracker]
fn safe_scalar_affine_from_bytes(bytes: &Bytes32) -> Result<Scalar, KzgError> {
    let lendian: [u8; 32] = Into::<[u8; 32]>::into(bytes.clone())
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

pub struct KzgProof {}

impl KzgProof {
    #[sp1_derive::cycle_tracker]
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

        let g2_x = G2Affine::generator() * z;
        let x_minus_z = kzg_settings.g2_points[1] - g2_x;

        let g1_y = G1Affine::generator() * y;
        let p_minus_y = commitment - g1_y;

        Ok(
            pairing(&p_minus_y.into(), &G2Affine::generator())
                == pairing(&proof, &x_minus_z.into()),
        )
    }
}

#[cfg(test)]
mod tests {
    use core::{
        mem::{self, transmute},
        slice,
    };
    use std::{
        fs,
        io::Write,
        path::{self, PathBuf},
    };

    use bls12_381::{G1Affine, G2Affine};

    use crate::{
        get_g1_points, test_format::Test, KzgProof, KzgSettings, BYTES_PER_G1_POINT, NUM_G1_POINTS,
    };

    const VERIFY_KZG_PROOF_TESTS: &str = "tests/verify_kzg_proof/*/*";

    // TODO: Move to script
    // #[test]
    // fn build_binary_file() {
    //     let kzg_settings = KzgSettings::load_trusted_setup_file();
    //     let g1_values = kzg_settings.g1_points.clone();
    //     let g2_values = kzg_settings.g2_points.clone();

    //     let mut g1_bytes: Vec<u8> = Vec::new();
    //     let mut g2_bytes: Vec<u8> = Vec::new();

    //     g1_values.iter().for_each(|&v| {
    //         g1_bytes.extend_from_slice(unsafe { &std::mem::transmute::<G1Affine, [u8; 104]>(v) });
    //     });

    //     g2_values.iter().for_each(|&v| {
    //         g2_bytes.extend_from_slice(unsafe { &std::mem::transmute::<G2Affine, [u8; 200]>(v) });
    //     });

    //     let mut g1_file = fs::OpenOptions::new()
    //         .create(true)
    //         .write(true)
    //         .open("g1.bin")
    //         .unwrap();

    //     g1_file.write_all(&g1_bytes).unwrap();

    //     let mut g2_file = fs::OpenOptions::new()
    //         .create(true)
    //         .write(true)
    //         .open("g2.bin")
    //         .unwrap();

    //     g2_file.write_all(&g2_bytes).unwrap();
    // }

    #[test]
    fn build_from_binary_file() {
        let g1_bytes = include_bytes!("g1.bin");
        let g1 = get_g1_points();
        // let g1: &[G1Affine] =
        //     unsafe { transmute(slice::from_raw_parts(g1_bytes.as_ptr(), NUM_G1_POINTS)) };
        println!("{:?}", g1);
        // G1Affine { x: 0x025a6f586726c68d45f00ad0f5a4436523317939a47713f78fd4fe81cd74236fdac1b04ecd97c2d0267d6f4981d7beb1, y: 0x09a1275f9efcc1e3166cdea9eff740ac675d8ec22fc07467f17c933e66ef3502e44dc20dcefd2f29621de1b9f64400f9, infinity: Choice(0) }

        // println!("{}", g1_bytes.len() / mem::size_of::<G1Affine>())
    }

    #[test]
    fn test_verify_kzg_proof() {
        let kzg_settings = KzgSettings::load_trusted_setup_file();
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

            let result = KzgProof::verify_kzg_proof(&commitment, &z, &y, &proof, &kzg_settings);
            match result {
                Ok(result) => {
                    assert_eq!(result, test.get_output().unwrap_or_else(|| false));
                }
                Err(e) => {
                    assert!(test.get_output().is_none());
                    eprintln!("Error: {:?}", e);
                }
            }
        }
    }
}
