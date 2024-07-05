use core::num::{NonZero, NonZeroUsize};

use crate::enums::KzgError;
use crate::trusted_setup::KzgSettings;
use crate::{
    dtypes::*, pairings_verify, BYTES_PER_BLOB, BYTES_PER_COMMITMENT, CHALLENGE_INPUT_SIZE,
    DOMAIN_STR_LENGTH, FIAT_SHAMIR_PROTOCOL_DOMAIN, NUM_FIELD_ELEMENTS_PER_BLOB,
};

use alloc::fmt::format;
use alloc::{string::ToString, vec::Vec};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use sha2::{Digest, Sha256};

fn safe_g1_affine_from_bytes(bytes: &Bytes48) -> Result<G1Affine, KzgError> {
    let g1 = G1Affine::from_compressed(&(bytes.clone().into()));
    if g1.is_none().into() {
        return Err(KzgError::BadArgs(
            "Failed to parse G1Affine from bytes".to_string(),
        ));
    }
    Ok(g1.unwrap())
}

pub(crate) fn safe_scalar_affine_from_bytes(bytes: &Bytes32) -> Result<Scalar, KzgError> {
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

/// Return the Fiat-Shamir challenge required to verify `blob` and `commitment`.
fn compute_challenge(blob: Blob, commitment: &G1Affine) -> Result<Scalar, KzgError> {
    let mut bytes = [0_u8; CHALLENGE_INPUT_SIZE];
    let mut offset = 0_usize;

    // Copy domain separator
    bytes[offset..DOMAIN_STR_LENGTH].copy_from_slice(FIAT_SHAMIR_PROTOCOL_DOMAIN.as_bytes());
    offset += DOMAIN_STR_LENGTH;

    // Copy polynomial degree (16-bytes, big-endian)
    bytes[offset..u64::BITS as usize].copy_from_slice(&0_u64.to_be_bytes());
    offset += u64::BITS as usize;
    bytes[offset..u64::BITS as usize]
        .copy_from_slice(&(NUM_FIELD_ELEMENTS_PER_BLOB as u64).to_be_bytes());
    offset += u64::BITS as usize;

    // Copy blob
    bytes[offset..BYTES_PER_BLOB].copy_from_slice(blob.as_slice());
    offset += BYTES_PER_BLOB;

    // Copy commitment
    bytes[offset..BYTES_PER_COMMITMENT].copy_from_slice(&commitment.to_compressed());
    offset += BYTES_PER_COMMITMENT;

    /* Make sure we wrote the entire buffer */

    if offset != CHALLENGE_INPUT_SIZE {
        return Err(KzgError::InvalidBytesLength(format!(
            "The challenge should be {} length, but was {}",
            CHALLENGE_INPUT_SIZE, offset,
        )));
    }

    let mut hasher = Sha256::new();
    hasher.update(bytes);

    let eval_challenge = hasher.finalize();
    let challenge = safe_scalar_affine_from_bytes(&Bytes32::from_slice(&eval_challenge)?)?;

    Ok(challenge)
}

/// Evaluates a polynomial in evaluation form at a given point
fn evaluate_polynomial_in_evaluation_form(
    polynomial: Vec<Scalar>,
    x: Scalar,
    kzg_settings: &KzgSettings,
) -> Result<Scalar, KzgError> {
    let mut inverses_in = vec![];
    let roots_of_unity = kzg_settings.roots_of_unity;

    for (i, _) in polynomial
        .iter()
        .enumerate()
        .take(NUM_FIELD_ELEMENTS_PER_BLOB)
    {
        // If the point to evaluate at is one of the evaluation points by which
        // the polynomial is given, we can just return the result directly.
        // Note that special-casing this is necessary, as the formula below
        // would divide by zero otherwise.
        if x == roots_of_unity[i] {
            return Ok(polynomial[i]);
        }
        inverses_in.push(x - roots_of_unity[i])
    }

    let inverses = batch_inversion(
        inverses_in,
        NonZero::new(NUM_FIELD_ELEMENTS_PER_BLOB).unwrap(),
    )?;

    let mut out = Scalar::zero();

    for i in 0..NUM_FIELD_ELEMENTS_PER_BLOB {
        out += (inverses[i] * roots_of_unity[i]) * polynomial[i];
    }

    out *= Scalar::from(NUM_FIELD_ELEMENTS_PER_BLOB as u64)
        .invert()
        .unwrap();
    out *= x.pow(&[NUM_FIELD_ELEMENTS_PER_BLOB as u64, 0, 0, 0]) - Scalar::one();

    Ok(out)
}

fn batch_inversion(a: Vec<Scalar>, len: NonZeroUsize) -> Result<Vec<Scalar>, KzgError> {
    let mut accumulator = Scalar::one();
    let mut out = vec![];

    for a in a.iter().take(len.into()) {
        out.push(accumulator);
        accumulator *= a;
    }

    if accumulator == Scalar::zero() {
        return Err(KzgError::BadArgs("Zero input is not allowed".to_string()));
    }

    accumulator = accumulator.invert().unwrap();

    for (i, out) in out.iter_mut().rev().enumerate() {
        *out *= accumulator;
        accumulator *= a[i];
    }

    Ok(out)
}

fn verify_kzg_proof_impl(
    commitment: G1Affine,
    z: Scalar,
    y: Scalar,
    proof: G1Affine,
    kzg_settings: &KzgSettings,
) -> Result<bool, KzgError> {
    let x = G2Projective::generator() * z;
    let x_minus_z = kzg_settings.g2_points[1] - x;

    let y = G1Projective::generator() * y;
    let p_minus_y = commitment - y;

    // Verify: P - y = Q * (X - z)
    Ok(pairings_verify(
        p_minus_y.into(),
        G2Projective::generator().into(),
        proof,
        x_minus_z.into(),
    ))
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

        let g2_x = G2Affine::generator() * z;
        let x_minus_z = kzg_settings.g2_points[1] - g2_x;

        let g1_y = G1Affine::generator() * y;
        let p_minus_y = commitment - g1_y;

        Ok(
            pairing(&p_minus_y.into(), &G2Affine::generator())
                == pairing(&proof, &x_minus_z.into()),
        )
    }

    pub fn verify_blob_kzg_proof(
        blob: Blob,
        commitment_bytes: &Bytes48,
        proof_bytes: &Bytes48,
        kzg_settings: &KzgSettings,
    ) -> Result<bool, KzgError> {
        let commitment = safe_g1_affine_from_bytes(commitment_bytes)?;
        let polynomial = blob.as_polynomial()?;
        let proof = safe_g1_affine_from_bytes(proof_bytes)?;

        // Compute challenge for the blob/commitment
        let evaluation_challenge = compute_challenge(blob, &commitment)?;

        let y =
            evaluate_polynomial_in_evaluation_form(polynomial, evaluation_challenge, kzg_settings)?;

        verify_kzg_proof_impl(commitment, evaluation_challenge, y, proof, kzg_settings)
    }

    pub fn verify_blob_kzg_proof_batch(
        blobs: Vec<Blob>,
        commitments_bytes: Vec<Bytes48>,
        proofs_bytes: Vec<Bytes48>,
        kzg_settings: &KzgSettings,
    ) -> Result<bool, KzgError> {
        // Exit early if we are given zero blobs
        if blobs.is_empty() {
            return Ok(true);
        }

        // For a single blob, just do a regular single verification
        if blobs.len() == 1 {
            return Self::verify_blob_kzg_proof(
                blobs[0].clone(),
                &commitments_bytes[0],
                &proofs_bytes[0],
                kzg_settings,
            );
        }

        todo!()
    }
}

#[cfg(feature = "std")]
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
    #[cfg(feature = "cache")]
    fn test_verify_kzg_proof() {
        let kzg_settings = KzgSettings::load_trusted_setup_file().unwrap();
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
