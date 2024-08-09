use std::num::NonZeroUsize;
use std::ops::Mul;

use crate::dtypes::*;
use crate::enums::KzgError;
use crate::trusted_setup::KzgSettings;
use crate::{
    BYTES_PER_BLOB, BYTES_PER_COMMITMENT, BYTES_PER_FIELD_ELEMENT, BYTES_PER_PROOF,
    CHALLENGE_INPUT_SIZE, DOMAIN_STR_LENGTH, FIAT_SHAMIR_PROTOCOL_DOMAIN, MODULUS,
    NUM_FIELD_ELEMENTS_PER_BLOB, RANDOM_CHALLENGE_KZG_BATCH_DOMAIN,
};
use ff::derive::sbb;

use alloc::{string::ToString, vec::Vec};
use sha2::{Digest, Sha256};
use zkvm_pairings::fp::Bls12381;
use zkvm_pairings::fr::Fr;
use zkvm_pairings::g1::G1Element;
use zkvm_pairings::g2::G2Projective;
use zkvm_pairings::{g1::G1Affine, g2::G2Affine, pairings::verify_pairing};

fn safe_g1_affine_from_bytes(bytes: &Bytes48) -> Result<G1Affine<Bls12381>, KzgError> {
    println!("Safe G1 Affine bytes [NEW]: {:?}", bytes.0);
    let g1 = G1Affine::<Bls12381>::from_compressed(&bytes.0);
    if g1.is_none().into() {
        return Err(KzgError::BadArgs(
            "Failed to parse G1Affine<Bls12381> from bytes".to_string(),
        ));
    }
    Ok(g1.unwrap())
}

pub(crate) fn safe_scalar_affine_from_bytes(bytes: &Bytes32) -> Result<Fr<Bls12381>, KzgError> {
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
            "Failed to parse G1Affine<Bls12381> from bytes".to_string(),
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
        let evaluation_challenge = compute_challenge(&blob, &commitment)?;

        let y =
            evaluate_polynomial_in_evaluation_form(polynomial, evaluation_challenge, kzg_settings)?;

        verify_kzg_proof_impl(commitment, evaluation_challenge, y, proof, kzg_settings)
    }

    // TODO(bharghav): Need to implement msm_variable_base for G1Affine and don't convery to G1Projective
    // pub fn verify_kzg_proof_batch(
    //     commitments: &[G1Affine<Bls12381>],
    //     zs: &[Fr<Bls12381>],
    //     ys: &[Fr<Bls12381>],
    //     proofs: &[G1Affine<Bls12381>],
    //     kzg_settings: &KzgSettings,
    // ) -> Result<bool, KzgError> {
    //     let n = commitments.len();
    //     let mut c_minus_y: Vec<G1Projective<Bls12381>> = Vec::with_capacity(n);
    //     let mut r_times_z: Vec<Fr<Bls12381>> = Vec::with_capacity(n);

    //     // Compute the random lincomb challenges
    //     let r_powers = compute_r_powers(commitments, zs, ys, proofs)?;

    //     // Compute \sum r^i * Proof_i
    //     let proofs = proofs.iter().map(Into::into).collect::<Vec<_>>();
    //     let proof_lincomb = G1Projective::msm_variable_base(&proofs, &r_powers);

    //     for i in 0..n {
    //         // Get [y_i]
    //         let ys_encrypted = G1Affine::generator() * ys[i];
    //         // Get C_i - [y_i]
    //         c_minus_y.push(commitments[i] - ys_encrypted);
    //         // Get r^i * z_i
    //         r_times_z.push(r_powers[i] * zs[i]);
    //     }

    //     // Get \sum r^i z_i Proof_i
    //     let proof_z_lincomb = G1Projective::msm_variable_base(&proofs, &r_times_z);
    //     // Get \sum r^i (C_i - [y_i])
    //     let c_minus_y_lincomb = G1Projective::msm_variable_base(&c_minus_y, &r_powers);

    //     // Get C_minus_y_lincomb + proof_z_lincomb
    //     let rhs_g1 = c_minus_y_lincomb + proof_z_lincomb;

    //     // Do the pairing check!
    //     Ok(Self::pairings_verify(
    //         proof_lincomb.into(),
    //         &kzg_settings.g2_points[1],
    //         rhs_g1.into(),
    //         &G2Affine::generator(),
    //     ))
    // }

    // pub fn verify_blob_kzg_proof_batch(
    //     blobs: Vec<Blob>,
    //     commitments_bytes: Vec<Bytes48>,
    //     proofs_bytes: Vec<Bytes48>,
    //     kzg_settings: &KzgSettings,
    // ) -> Result<bool, KzgError> {
    //     // Exit early if we are given zero blobs
    //     if blobs.is_empty() {
    //         return Ok(true);
    //     }

    //     // For a single blob, just do a regular single verification
    //     if blobs.len() == 1 {
    //         return Self::verify_blob_kzg_proof(
    //             blobs[0].clone(),
    //             &commitments_bytes[0],
    //             &proofs_bytes[0],
    //             kzg_settings,
    //         );
    //     }

    //     if blobs.len() != commitments_bytes.len() {
    //         return Err(KzgError::InvalidBytesLength(
    //             "Invalid commitments length".to_string(),
    //         ));
    //     }

    //     if blobs.len() != proofs_bytes.len() {
    //         return Err(KzgError::InvalidBytesLength(
    //             "Invalid proofs length".to_string(),
    //         ));
    //     }

    //     let commitments = commitments_bytes
    //         .iter()
    //         .map(safe_g1_affine_from_bytes)
    //         .collect::<Result<Vec<_>, _>>()?;

    //     let proofs = proofs_bytes
    //         .iter()
    //         .map(safe_g1_affine_from_bytes)
    //         .collect::<Result<Vec<_>, _>>()?;

    //     validate_batched_input(&commitments, &proofs)?;

    //     let (evaluation_challenges, ys) =
    //         compute_challenges_and_evaluate_polynomial(blobs, &commitments, kzg_settings)?;

    //     Self::verify_kzg_proof_batch(
    //         &commitments,
    //         &evaluation_challenges,
    //         &ys,
    //         &proofs,
    //         kzg_settings,
    //     )
    // }

    fn pairings_verify(
        a1: &G1Affine<Bls12381>,
        a2: &G2Affine<Bls12381>,
        b1: &G1Affine<Bls12381>,
        b2: &G2Affine<Bls12381>,
    ) -> bool {
        verify_pairing(&[-*a1, *b1], &[*a2, *b2])
    }
}

/// Return the Fiat-Shamir challenge required to verify `blob` and `commitment`.
fn compute_challenge(
    blob: &Blob,
    commitment: &G1Affine<Bls12381>,
) -> Result<Fr<Bls12381>, KzgError> {
    let mut bytes = [0_u8; CHALLENGE_INPUT_SIZE];
    let mut offset = 0_usize;

    // Copy domain separator
    bytes[offset..DOMAIN_STR_LENGTH].copy_from_slice(FIAT_SHAMIR_PROTOCOL_DOMAIN.as_bytes());
    offset += DOMAIN_STR_LENGTH;

    // Copy polynomial degree (16-bytes, big-endian)
    bytes[offset..offset + 8].copy_from_slice(&0_u64.to_be_bytes());
    offset += 8;
    bytes[offset..offset + 8].copy_from_slice(&(NUM_FIELD_ELEMENTS_PER_BLOB as u64).to_be_bytes());
    offset += 8;

    // Copy blob
    bytes[offset..offset + BYTES_PER_BLOB].copy_from_slice(&blob.0);
    offset += BYTES_PER_BLOB;

    // Copy commitment
    let mut compressed_commitment = [0_u8; 48];
    (*commitment).to_compressed(&mut compressed_commitment);
    bytes[offset..offset + BYTES_PER_COMMITMENT].copy_from_slice(&compressed_commitment);
    offset += BYTES_PER_COMMITMENT;

    /* Make sure we wrote the entire buffer */

    if offset != CHALLENGE_INPUT_SIZE {
        return Err(KzgError::InvalidBytesLength(format!(
            "The challenge should be {} length, but was {}",
            CHALLENGE_INPUT_SIZE, offset,
        )));
    }

    let evaluation: [u8; 32] = Sha256::digest(bytes).into();

    Ok(scalar_from_bytes_unchecked(evaluation))
}

fn scalar_from_bytes_unchecked(bytes: [u8; 32]) -> Fr<Bls12381> {
    scalar_from_u64_array_unchecked([
        u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[0..8]).unwrap()),
        u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap()),
        u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap()),
        u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap()),
    ])
}

fn scalar_from_u64_array_unchecked(array: [u64; 4]) -> Fr<Bls12381> {
    // Try to subtract the modulus
    let (_, borrow) = sbb(array[0], MODULUS[0], 0);
    let (_, borrow) = sbb(array[1], MODULUS[1], borrow);
    let (_, borrow) = sbb(array[2], MODULUS[2], borrow);
    let (_, _borrow) = sbb(array[3], MODULUS[3], borrow);

    Fr::<Bls12381>::from_raw_unchecked([array[3], array[2], array[1], array[0]])
}

/// Evaluates a polynomial in evaluation form at a given point
fn evaluate_polynomial_in_evaluation_form(
    polynomial: Vec<Fr<Bls12381>>,
    x: Fr<Bls12381>,
    kzg_settings: &KzgSettings,
) -> Result<Fr<Bls12381>, KzgError> {
    if polynomial.len() != NUM_FIELD_ELEMENTS_PER_BLOB {
        return Err(KzgError::InvalidBytesLength(
            "The polynomial length is incorrect".to_string(),
        ));
    }

    let mut inverses_in = vec![Fr::<Bls12381>::default(); NUM_FIELD_ELEMENTS_PER_BLOB];
    let mut inverses = vec![Fr::<Bls12381>::default(); NUM_FIELD_ELEMENTS_PER_BLOB];
    let roots_of_unity = kzg_settings.roots_of_unity;

    for i in 0..NUM_FIELD_ELEMENTS_PER_BLOB {
        // If the point to evaluate at is one of the evaluation points by which
        // the polynomial is given, we can just return the result directly.
        // Note that special-casing this is necessary, as the formula below
        // would divide by zero otherwise.
        if x == roots_of_unity[i] {
            return Ok(polynomial[i]);
        }
        inverses_in[i] = x - roots_of_unity[i];
    }

    batch_inversion(
        &mut inverses,
        &inverses_in,
        NonZeroUsize::new(NUM_FIELD_ELEMENTS_PER_BLOB).unwrap(),
    )?;

    let mut out = Fr::<Bls12381>::zero();

    for i in 0..NUM_FIELD_ELEMENTS_PER_BLOB {
        out += (inverses[i] * roots_of_unity[i]) * polynomial[i];
    }

    out *= Fr::<Bls12381>::from(NUM_FIELD_ELEMENTS_PER_BLOB as u64)
        .invert()
        .unwrap();
    out *= x.pow_vartime(&[NUM_FIELD_ELEMENTS_PER_BLOB as u64, 0, 0, 0]) - Fr::<Bls12381>::one();

    Ok(out)
}

fn batch_inversion(
    out: &mut [Fr<Bls12381>],
    a: &[Fr<Bls12381>],
    len: NonZeroUsize,
) -> Result<(), KzgError> {
    if a == out {
        return Err(KzgError::BadArgs(
            "Destination is the same as source".to_string(),
        ));
    }

    let mut accumulator = Fr::<Bls12381>::one();

    for i in 0..len.into() {
        out[i] = accumulator;
        accumulator = accumulator.mul(&a[i]);
    }

    if accumulator == Fr::<Bls12381>::zero() {
        return Err(KzgError::BadArgs("Zero input".to_string()));
    }

    accumulator = accumulator.invert().unwrap();

    for i in (0..len.into()).rev() {
        out[i] *= accumulator;
        accumulator *= a[i];
    }

    Ok(())
}

fn verify_kzg_proof_impl(
    commitment: G1Affine<Bls12381>,
    z: Fr<Bls12381>,
    y: Fr<Bls12381>,
    proof: G1Affine<Bls12381>,
    kzg_settings: &KzgSettings,
) -> Result<bool, KzgError> {
    // let x = G2Projective::generator() * z;
    let x = G2Affine::generator() * z;
    let x_minus_z = kzg_settings.g2_points[1] - x;

    // let y = G1Projective::generator() * y;
    let y = G1Affine::generator() * y;
    let p_minus_y = commitment - y;

    // Verify: P - y = Q * (X - z)
    Ok(KzgProof::pairings_verify(
        &p_minus_y,
        // G2Projective::generator(),
        &G2Affine::<Bls12381>::generator(),
        &proof,
        &x_minus_z,
    ))
}

fn validate_batched_input(
    commitments: &[G1Affine<Bls12381>],
    proofs: &[G1Affine<Bls12381>],
) -> Result<(), KzgError> {
    let invalid_commitment = commitments.iter().any(|commitment| {
        !bool::from(commitment.is_identity()) && !bool::from(commitment.is_on_curve())
    });

    let invalid_proof = proofs
        .iter()
        .any(|proof| !bool::from(proof.is_identity()) && !bool::from(proof.is_on_curve()));

    if invalid_commitment {
        return Err(KzgError::BadArgs("Invalid commitment".to_string()));
    }
    if invalid_proof {
        return Err(KzgError::BadArgs("Invalid proof".to_string()));
    }

    Ok(())
}

fn compute_challenges_and_evaluate_polynomial(
    blobs: Vec<Blob>,
    commitments: &[G1Affine<Bls12381>],
    kzg_settings: &KzgSettings,
) -> Result<(Vec<Fr<Bls12381>>, Vec<Fr<Bls12381>>), KzgError> {
    let mut evaluation_challenges = Vec::with_capacity(blobs.len());
    let mut ys = Vec::with_capacity(blobs.len());

    for i in 0..blobs.len() {
        let polynomial = blobs[i].as_polynomial()?;
        let evaluation_challenge = compute_challenge(&blobs[i], &commitments[i])?;
        let y =
            evaluate_polynomial_in_evaluation_form(polynomial, evaluation_challenge, kzg_settings)?;

        evaluation_challenges.push(evaluation_challenge);
        ys.push(y);
    }

    Ok((evaluation_challenges, ys))
}

pub fn compute_powers(base: &Fr<Bls12381>, num_powers: usize) -> Vec<Fr<Bls12381>> {
    let mut powers = vec![Fr::<Bls12381>::default(); num_powers];
    if num_powers == 0 {
        return powers;
    }
    powers[0] = Fr::<Bls12381>::one();
    for i in 1..num_powers {
        powers[i] = powers[i - 1].mul(base);
    }
    powers
}

fn compute_r_powers(
    commitments: &[G1Affine<Bls12381>],
    zs: &[Fr<Bls12381>],
    ys: &[Fr<Bls12381>],
    proofs: &[G1Affine<Bls12381>],
) -> Result<Vec<Fr<Bls12381>>, KzgError> {
    let n = commitments.len();
    let input_size =
        32 + n * (BYTES_PER_COMMITMENT + 2 * BYTES_PER_FIELD_ELEMENT + BYTES_PER_PROOF);

    let mut bytes: Vec<u8> = vec![0; input_size];

    // Copy domain separator
    bytes[..16].copy_from_slice(RANDOM_CHALLENGE_KZG_BATCH_DOMAIN.as_bytes());

    bytes[16..24].copy_from_slice(&(NUM_FIELD_ELEMENTS_PER_BLOB as u64).to_be_bytes());
    bytes[24..32].copy_from_slice(&n.to_be_bytes());

    let mut offset = 32;

    for i in 0..n {
        // Copy commitment
        let mut compressed_commitment = [0_u8; 48];
        (commitments[i]).to_compressed(&mut compressed_commitment);
        bytes[offset..(compressed_commitment.len() + offset)]
            .copy_from_slice(&compressed_commitment[..]);
        offset += BYTES_PER_COMMITMENT;

        // Copy evaluation challenge
        let v = zs[i].to_bytes();
        bytes[offset..(v.len() + offset)].copy_from_slice(&v[..]);
        offset += BYTES_PER_FIELD_ELEMENT;

        // Copy polynomial's evaluation value
        let v = ys[i].to_bytes();
        bytes[offset..(v.len() + offset)].copy_from_slice(&v[..]);
        offset += BYTES_PER_FIELD_ELEMENT;

        // Copy proof
        let mut compressed_proof = [0_u8; 48];
        (proofs[i]).to_compressed(&mut compressed_proof);
        bytes[offset..(compressed_proof.len() + offset)].copy_from_slice(&compressed_proof[..]);
        offset += BYTES_PER_PROOF;
    }

    // Make sure we wrote the entire buffer
    if offset != input_size {
        return Err(KzgError::InvalidBytesLength(
            "Error while copying commitments".to_string(),
        ));
    }

    // Now let's create the challenge!
    let evaluation: [u8; 32] = Sha256::digest(bytes).into();
    let r = scalar_from_bytes_unchecked(evaluation);

    Ok(compute_powers(&r, n))
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
