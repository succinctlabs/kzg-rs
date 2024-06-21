# kzg-rs [![Rust](https://github.com/0xWOLAND/kzg-rs/actions/workflows/rust.yml/badge.svg?branch=master)](https://github.com/0xWOLAND/kzg-rs/actions/workflows/rust.yml)

An endpoint for `verify_kzg_proof` in [c-kzg-4844](https://github.com/ethereum/c-kzg-4844) using [bls12_381](https://github.com/zkcrypto/bls12_381/). Passes all of the `verify_kzg_proof` tests in [c-kzg-4844/verify_kzg_proof](https://github.com/ethereum/c-kzg-4844/tree/main/tests/verify_kzg_proof/kzg-mainnet).

## Cycle Counts in SP1

| Operation            | Cycle Count |
| -------------------- | ----------- |
| `verify_kzg_proof`   | 276,957,860 |
| `load_trusted_setup` | 391         |

Checkout the SP1 profile at [0xWOLAND/sp1-revm-kzg-profile](https://github.com/0xWOLAND/sp1-revm-kzg-profile). This crate has been used in a [fork of SP1's patch of `revm`](https://github.com/0xWOLAND/revm/tree/patch-v5.0.0), which passes all tests. Additionally, `kzg-rs` is based on [this](https://github.com/0xWOLAND/bls12_381) slightly modified fork of `bls12_381`.
