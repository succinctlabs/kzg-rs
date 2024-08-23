#[allow(unused_imports)]
use bls12_381::{multi_miller_loop, G1Affine, G2Affine, G2Prepared, Gt, Scalar};

/// Verifies the pairing of two G1 and two G2 points are equivalent using the multi-miller loop
pub fn pairings_verify(a1: G1Affine, a2: G2Affine, b1: G1Affine, b2: G2Affine) -> bool {
    multi_miller_loop(&[(&-a1, &G2Prepared::from(a2)), (&b1, &G2Prepared::from(b2))])
        .final_exponentiation()
        == Gt::identity()
}
