use std::{fs, io::Write};

use bls12_381::{G1Affine, G2Affine};
use kzg_rs::{load_trusted_setup_file_brute, KzgSettings, KzgSettingsOwned};

fn main() {
    let KzgSettingsOwned {
        max_width: _,
        g1_points,
        g2_points,
    } = load_trusted_setup_file_brute().unwrap();

    let mut g1_bytes: Vec<u8> = Vec::new();
    let mut g2_bytes: Vec<u8> = Vec::new();

    g1_points.iter().for_each(|&v| {
        g1_bytes.extend_from_slice(unsafe { &std::mem::transmute::<G1Affine, [u8; 104]>(v) });
    });

    g2_points.iter().for_each(|&v| {
        g2_bytes.extend_from_slice(unsafe { &std::mem::transmute::<G2Affine, [u8; 200]>(v) });
    });

    let mut g1_file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open("src/g1.bin")
        .unwrap();

    g1_file.write_all(&g1_bytes).unwrap();

    let mut g2_file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open("src/g2.bin")
        .unwrap();

    g2_file.write_all(&g2_bytes).unwrap();
}
