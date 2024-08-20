use std::{fs, io::Write};
const TRUSTED_SETUP_FILE: &str = include_str!("src/trusted_setup.txt");

include!("src/enums.rs");
include!("src/consts.rs");
include!("src/pairings.rs");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KzgSettingsOwned {
    pub roots_of_unity: [Scalar; NUM_ROOTS_OF_UNITY],
    pub g1_points: [G1Affine; NUM_G1_POINTS],
    pub g2_points: [G2Affine; NUM_G2_POINTS],
}

fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, KzgError> {
    let trimmed_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(trimmed_str)
        .map_err(|e| KzgError::InvalidHexFormat(format!("Failed to decode hex: {}", e)))
}


pub fn load_trusted_setup_file_brute() -> Result<KzgSettingsOwned, KzgError> {
    let trusted_setup_file: Vec<String> = TRUSTED_SETUP_FILE
        .split('\n')
        .map(|x| x.to_string())
        .collect();

    let num_g1_points = trusted_setup_file[0].parse::<usize>().unwrap();
    let num_g2_points = trusted_setup_file[1].parse::<usize>().unwrap();
    let g1_points_idx = num_g1_points + 2;
    let g2_points_idx = g1_points_idx + num_g2_points;

    let _g1_points: Vec<[u8; BYTES_PER_G1_POINT]> =
        hex_to_bytes(&trusted_setup_file[2..g1_points_idx].join(""))
            .unwrap()
            .chunks_exact(BYTES_PER_G1_POINT)
            .map(|chunk| {
                let mut array = [0u8; BYTES_PER_G1_POINT];
                array.copy_from_slice(chunk);
                array
            })
            .collect();
    let _g2_points: Vec<[u8; BYTES_PER_G2_POINT]> =
        hex_to_bytes(&trusted_setup_file[g1_points_idx..g2_points_idx].join(""))
            .unwrap()
            .chunks_exact(BYTES_PER_G2_POINT)
            .map(|chunk| {
                let mut array = [0u8; BYTES_PER_G2_POINT];
                array.copy_from_slice(chunk);
                array
            })
            .collect();

    assert_eq!(_g1_points.len(), num_g1_points);
    assert_eq!(_g2_points.len(), num_g2_points);

    let mut max_scale = 0;
    while (1 << max_scale) < _g1_points.len() {
        max_scale += 1;
    }

    let roots_of_unity = compute_roots_of_unity(max_scale)?;
    let mut g1_points: [G1Affine; NUM_G1_POINTS] = [G1Affine::identity(); NUM_G1_POINTS];
    let mut g2_points: [G2Affine; NUM_G2_POINTS] = [G2Affine::identity(); NUM_G2_POINTS];

    _g1_points.iter().enumerate().for_each(|(i, bytes)| {
        g1_points[i] = G1Affine::from_compressed_unchecked(bytes)
            .expect("load_trusted_setup Invalid g1 bytes");
    });

    _g2_points.iter().enumerate().for_each(|(i, bytes)| {
        g2_points[i] = G2Affine::from_compressed_unchecked(bytes)
            .expect("load_trusted_setup Invalid g2 bytes");
    });

    let _ = is_trusted_setup_in_lagrange_form(&g1_points, &g2_points);

    let bit_reversed_permutation = bit_reversal_permutation(&g1_points)?;
    let g1_points = bit_reversed_permutation;

    Ok(KzgSettingsOwned {
        roots_of_unity,
        g1_points,
        g2_points,
    })
}

fn bit_reversal_permutation<T, const N: usize>(array: &[T]) -> Result<[T; N], KzgError>
where
    T: Default + Copy,
{
    let n = array.len();
    assert!(n.is_power_of_two(), "n must be a power of 2");

    let mut bit_reversed_permutation = [T::default(); N];
    let unused_bit_len = array.len().leading_zeros();

    for (i, item) in array.iter().enumerate().take(n) {
        let r = i.reverse_bits() >> (unused_bit_len + 1);
        bit_reversed_permutation[r] = *item;
    }

    Ok(bit_reversed_permutation)
}

fn is_trusted_setup_in_lagrange_form(
    g1_points: &[G1Affine],
    g2_points: &[G2Affine],
) -> Result<(), KzgError> {
    let n1 = g1_points.len();
    let n2 = g2_points.len();

    if n1 < 2 || n2 < 2 {
        return Err(KzgError::BadArgs("invalid args".to_string()));
    }

    let a1 = g1_points[1];
    let a2 = g2_points[0];
    let b1 = g1_points[0];
    let b2 = g2_points[1];

    let is_monomial_form = pairings_verify(a1, a2, b1, b2);
    if !is_monomial_form {
        return Err(KzgError::BadArgs("not in monomial form".to_string()));
    }

    Ok(())
}

fn compute_roots_of_unity<const N: usize>(max_scale: usize) -> Result<[Scalar; N], KzgError> {
    if max_scale >= SCALE2_ROOT_OF_UNITY.len() {
        return Err(KzgError::BadArgs(format!(
            "The max scale should be lower than {}",
            SCALE2_ROOT_OF_UNITY.len()
        )));
    }

    let root_of_unity = Scalar::from_raw(SCALE2_ROOT_OF_UNITY[max_scale]);
    let mut expanded_roots = expand_root_of_unity(root_of_unity, N)?;
    let _ = expanded_roots.pop();

    bit_reversal_permutation(&expanded_roots)
}

fn expand_root_of_unity(root: Scalar, width: usize) -> Result<Vec<Scalar>, KzgError> {
    if width < 2 {
        return Err(KzgError::BadArgs(
            "The width must be greater or equal to 2".to_string(),
        ));
    }

    let mut expanded = vec![Scalar::one(), root];

    for _ in 2..=width {
        let current = expanded.last().unwrap() * root;
        expanded.push(current);
        if current == Scalar::one() {
            break;
        }
    }

    if expanded.last().unwrap() != &Scalar::one() {
        return Err(KzgError::InvalidBytesLength(
            "The last element value should be equal to 1".to_string(),
        ));
    }

    Ok(expanded)
}

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
