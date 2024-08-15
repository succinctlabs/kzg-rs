use alloc::vec::Vec;
use bls12_381::{G1Projective, Scalar};

fn ln_without_floats(a: usize) -> usize {
    (log2(a) * 69 / 100) as usize
}

fn log2(x: usize) -> u32 {
    if x <= 1 {
        return 0;
    }

    let n = x.leading_zeros();
    core::mem::size_of::<usize>() as u32 * 8 - n
}

/// Divide `self` by n.
#[inline]
pub fn divn(x: &Scalar, n: u32) -> Scalar {
    if n >= 256 {
        return Scalar::from(0);
    }

    Scalar::from(n as u64).invert().unwrap() * x
}

/// Performs a Variable Base Multiscalar Multiplication.
pub fn msm_variable_base(points: &[G1Projective], scalars: &[Scalar]) -> G1Projective {
    let c = if scalars.len() < 32 {
        3
    } else {
        ln_without_floats(scalars.len()) + 2
    };

    let num_bits = 255usize;
    let fr_one = Scalar::one();

    let zero = G1Projective::identity();
    let window_starts: Vec<_> = (0..num_bits).step_by(c).collect();

    let window_starts_iter = window_starts.into_iter();

    // Each window is of size `c`.
    // We divide up the bits 0..num_bits into windows of size `c`, and
    // in parallel process each such window.
    let window_sums: Vec<_> = window_starts_iter
        .map(|w_start| {
            let mut res = zero;
            // We don't need the "zero" bucket, so we only have 2^c - 1 buckets
            let mut buckets = vec![zero; (1 << c) - 1];
            scalars
                .iter()
                .zip(points)
                .filter(|(s, _)| !(*s == &Scalar::zero()))
                .for_each(|(&scalar, base)| {
                    if scalar == fr_one {
                        // We only process unit scalars once in the first window.
                        if w_start == 0 {
                            res = res.add(base);
                        }
                    } else {
                        let mut scalar = Scalar::montgomery_reduce(
                            scalar.0[0],
                            scalar.0[1],
                            scalar.0[2],
                            scalar.0[3],
                            0,
                            0,
                            0,
                            0,
                        );

                        // We right-shift by w_start, thus getting rid of the
                        // lower bits.
                        scalar = divn(&scalar, w_start as u32);
                        // We mod the remaining bits by the window size.
                        let scalar = scalar.0[0] % (1 << c);

                        // If the scalar is non-zero, we update the corresponding
                        // bucket.
                        // (Recall that `buckets` doesn't have a zero bucket.)
                        if scalar != 0 {
                            buckets[(scalar - 1) as usize] =
                                buckets[(scalar - 1) as usize].add(base);
                        }
                    }
                });

            let mut running_sum = G1Projective::identity();
            for b in buckets.into_iter().rev() {
                running_sum += b;
                res += &running_sum;
            }

            res
        })
        .collect();

    // We store the sum for the lowest window.
    let lowest = *window_sums.first().unwrap();
    // We're traversing windows from high to low.
    window_sums[1..]
        .iter()
        .rev()
        .fold(zero, |mut total, sum_i| {
            total += sum_i;
            for _ in 0..c {
                total = total.double();
            }
            total
        })
        + lowest
}
