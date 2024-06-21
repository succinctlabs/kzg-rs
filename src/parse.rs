// use crate::{G1Points, G2Points, KzgSettings, NUM_G1_POINTS, NUM_G2_POINTS};
// use bls12_381::{fp::Fp, fp2::Fp2, G1Affine, G2Affine};
// use serde_json::Value;
// use subtle::Choice;

// const TRUSTED_SETUP_JSON: &str = include_str!("trusted_setup.json");

// pub(crate) fn get_trusted_setup() -> KzgSettings {
//     let json: Value = serde_json::from_str(TRUSTED_SETUP_JSON).unwrap();
//     let max_width = json["max_width"].as_u64().unwrap() as usize;

//     let mut g1_points: G1Points = [G1Affine::default(); NUM_G1_POINTS];

//     json["g1_values"]
//         .as_array()
//         .unwrap()
//         .iter()
//         .enumerate()
//         .for_each(|(i, entry)| {
//             let x = Fp((&entry["x"])
//                 .as_array()
//                 .map(|xs| xs.iter().map(|x| x.as_u64().unwrap()).collect::<Vec<u64>>())
//                 .unwrap()
//                 .clone()
//                 .try_into()
//                 .unwrap());
//             let y = Fp((&entry["y"])
//                 .as_array()
//                 .map(|ys| ys.iter().map(|y| y.as_u64().unwrap()).collect::<Vec<u64>>())
//                 .unwrap()
//                 .clone()
//                 .try_into()
//                 .unwrap());
//             let infinity = Choice::from(entry["infinity"].as_u64().unwrap() as u8);
//             g1_points[i] = G1Affine { x, y, infinity };
//         });

//     let mut g2_points: G2Points = [G2Affine::default(); NUM_G2_POINTS];
//     json["g2_values"]
//         .as_array()
//         .unwrap()
//         .iter()
//         .enumerate()
//         .for_each(|(i, entry)| {
//             let x = Fp2 {
//                 c0: Fp((&entry["x"]["c0"])
//                     .as_array()
//                     .unwrap()
//                     .iter()
//                     .map(|x| x.as_u64().unwrap())
//                     .collect::<Vec<u64>>()
//                     .try_into()
//                     .unwrap()),
//                 c1: Fp((&entry["x"]["c1"])
//                     .as_array()
//                     .unwrap()
//                     .iter()
//                     .map(|x| x.as_u64().unwrap())
//                     .collect::<Vec<u64>>()
//                     .try_into()
//                     .unwrap()),
//             };
//             let y = Fp2 {
//                 c0: Fp((&entry["y"]["c0"])
//                     .as_array()
//                     .unwrap()
//                     .iter()
//                     .map(|y| y.as_u64().unwrap())
//                     .collect::<Vec<u64>>()
//                     .try_into()
//                     .unwrap()),
//                 c1: Fp((&entry["y"]["c1"])
//                     .as_array()
//                     .unwrap()
//                     .iter()
//                     .map(|y| y.as_u64().unwrap())
//                     .collect::<Vec<u64>>()
//                     .try_into()
//                     .unwrap()),
//             };
//             let infinity = Choice::from(entry["infinity"].as_u64().unwrap() as u8);
//             g2_points[i] = G2Affine { x, y, infinity };
//         });

//     KzgSettings {
//         max_width,
//         g1_points: g1_points.clone(),
//         g2_points: g2_points.clone(),
//     }
// }
