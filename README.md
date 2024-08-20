# kzg-rs [![Rust](https://github.com/0xWOLAND/kzg-rs/actions/workflows/rust.yml/badge.svg?branch=master)](https://github.com/0xWOLAND/kzg-rs/actions/workflows/rust.yml)

An endpoint for `verify_kzg_proof` in [c-kzg-4844](https://github.com/ethereum/c-kzg-4844) using [bls12_381](https://github.com/zkcrypto/bls12_381/). Passes all of the `verify_kzg_proof` tests in [c-kzg-4844/verify_kzg_proof](https://github.com/ethereum/c-kzg-4844/tree/main/tests/verify_kzg_proof/kzg-mainnet).

## Cycle Counts in SP1

| Operation                     | Cycle Count       |
| ----------------------------- | ----------------- |
| `verify_blob_kzg_proof`       | 27,166,240 cycles |
| `verify_blob_kzg_proof_batch` | 27,363,307 cycles |
| `verify_kzg_proof`            | 9,390,640 cycles  |

This crate has been used in a [fork of SP1's patch of `revm`](https://github.com/0xWOLAND/revm/tree/patch-v5.0.0), which passes all tests.  `kzg-rs` is based on [this](https://github.com/0xWOLAND/bls12_381) slightly modified fork of `bls12_381`. This crate works in `[no_std]` mode.

## Usage
```sh
cargo add kzg-rs
```
Or add
```toml
kzg-rs = { version = "0.1" }
```

You can rebuild `roots_of_unity.bin`, `g1.bin`, and `g2.bin` by running 

```sh 
cargo build
```
