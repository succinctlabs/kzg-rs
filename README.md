# sp1-kzg

An endpoint for `verify_kzg_proof` for [c-kzg-4844](https://github.com/ethereum/c-kzg-4844) using [bls12_381](https://github.com/zkcrypto/bls12_381/). Passes all of the `verify_kzg_proof` tests in [c-kzg-4844/verify_kzg_proof](https://github.com/ethereum/c-kzg-4844/tree/main/tests/verify_kzg_proof/kzg-mainnet).

## Cycle Counts in SP1

| Operation            | Cycle Count                           |
| -------------------- | ------------------------------------- |
| `verify_kzg_proof`   | 276,957,860                           |
| Uncompress G2 Points | 11,511,799 cycles $\times$ 65 points  |
| Uncompress G1 Points | 1,835,836 cycles $\times$ 4096 points |

In total, lazy loading the trusted setup file costs 8,737,917,765 cycles.