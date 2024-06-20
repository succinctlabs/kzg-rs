use crate::KzgSettings;
use bls12_381::{fp::Fp, fp2::Fp2, G1Affine, G2Affine};
use serde_json::Value;
use subtle::Choice;

const TRUSTED_SETUP_FILE: &str = include_str!("trusted_setup.json");

pub(crate) fn get_trusted_setup() -> KzgSettings {
    let json: Value = serde_json::from_str(TRUSTED_SETUP_FILE).unwrap();
    let max_width = json["max_width"].as_u64().unwrap() as usize;

    let g1_values: Vec<G1Affine> = json["g1_values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let x = Fp((&entry["x"])
                .as_array()
                .map(|xs| xs.iter().map(|x| x.as_u64().unwrap()).collect::<Vec<u64>>())
                .unwrap()
                .clone()
                .try_into()
                .unwrap());
            let y = Fp((&entry["y"])
                .as_array()
                .map(|ys| ys.iter().map(|y| y.as_u64().unwrap()).collect::<Vec<u64>>())
                .unwrap()
                .clone()
                .try_into()
                .unwrap());
            let infinity = Choice::from(entry["infinity"].as_u64().unwrap() as u8);
            G1Affine { x, y, infinity }
        })
        .collect();

    let g2_values: Vec<G2Affine> = json["g2_values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let x = Fp2 {
                c0: Fp((&entry["x"]["c0"])
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_u64().unwrap())
                    .collect::<Vec<u64>>()
                    .try_into()
                    .unwrap()),
                c1: Fp((&entry["x"]["c1"])
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_u64().unwrap())
                    .collect::<Vec<u64>>()
                    .try_into()
                    .unwrap()),
            };
            let y = Fp2 {
                c0: Fp((&entry["y"]["c0"])
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|y| y.as_u64().unwrap())
                    .collect::<Vec<u64>>()
                    .try_into()
                    .unwrap()),
                c1: Fp((&entry["y"]["c1"])
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|y| y.as_u64().unwrap())
                    .collect::<Vec<u64>>()
                    .try_into()
                    .unwrap()),
            };
            let infinity = Choice::from(entry["infinity"].as_u64().unwrap() as u8);
            G2Affine { x, y, infinity }
        })
        .collect();

    KzgSettings {
        max_width,
        g1_values,
        g2_values,
    }
}
