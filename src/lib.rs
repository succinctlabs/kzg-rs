use bls12_381::{pairing, G1Affine, G2Affine, Scalar};
use trusted_setup::KzgSettings;

pub mod consts;
pub mod enums;
pub mod trusted_setup;

pub type Bytes32 = [u8; 32];
pub type Bytes48 = [u8; 48];

pub fn verify_kzg_proof(
    commitment_bytes: Bytes48,
    z_bytes: Bytes32,
    y_bytes: Bytes32,
    proof_bytes: Bytes48,
    kzg_settings: KzgSettings,
) -> bool {
    let commitment = G1Affine::from_compressed(&commitment_bytes).unwrap();
    let z = Scalar::from_bytes(&z_bytes).unwrap();
    let y = Scalar::from_bytes(&y_bytes).unwrap();
    let proof = G1Affine::from_compressed(&proof_bytes).unwrap();

    let g2_x = G2Affine::generator() * z;
    let x_minus_z = kzg_settings.g2_values[1] - g2_x;

    let g1_y = G1Affine::generator() * y;
    let p_minus_y = commitment - g1_y;

    pairing(&p_minus_y.into(), &G2Affine::generator()) == pairing(&proof, &x_minus_z.into())
}

#[cfg(test)]
mod tests {
    use crate::trusted_setup;

    #[test]
    fn test_verify_kzg_proof() {
        let kzg_settings = trusted_setup::load_trusted_setup_file().unwrap();
        println!("{:?}", kzg_settings);
    }
}
