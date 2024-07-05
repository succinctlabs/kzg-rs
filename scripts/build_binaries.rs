use std::{fs, io::Write};

use bls12_381::{G1Affine, G2Affine, Scalar};
use kzg_rs::{load_trusted_setup_file_brute, KzgSettingsOwned};

fn main() {
    let KzgSettingsOwned {
        roots_of_unity,
        g1_points,
        g2_points,
    } = load_trusted_setup_file_brute().unwrap();

    let mut roots_of_unity_bytes: Vec<u8> = Vec::new();
    let mut g1_bytes: Vec<u8> = Vec::new();
    let mut g2_bytes: Vec<u8> = Vec::new();

    roots_of_unity.iter().for_each(|&v| {
        roots_of_unity_bytes
            .extend_from_slice(unsafe { &std::mem::transmute::<Scalar, [u8; 32]>(v) });
    });

    g1_points.iter().for_each(|&v| {
        g1_bytes.extend_from_slice(unsafe { &std::mem::transmute::<G1Affine, [u8; 104]>(v) });
    });

    g2_points.iter().for_each(|&v| {
        g2_bytes.extend_from_slice(unsafe { &std::mem::transmute::<G2Affine, [u8; 200]>(v) });
    });

    let mut roots_of_unity_file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open("src/roots_of_unity.bin")
        .unwrap();

    roots_of_unity_file
        .write_all(&roots_of_unity_bytes)
        .unwrap();

    let mut g1_file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open("src/g1.bin")
        .unwrap();

    g1_file.write_all(&g1_bytes).unwrap();

    let mut g2_file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open("src/g2.bin")
        .unwrap();

    g2_file.write_all(&g2_bytes).unwrap();
}
