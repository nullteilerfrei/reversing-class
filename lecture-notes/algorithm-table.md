# Identification Help for Known Algorithms

## Cryptography

| Name     | Help                                                                                                                                         |
|----------|----------------------------------------------------------------------------------------------------------------------------------------------|
| RC4      | a buffer is initialized with incrementing integer values                                                                                     |
| SEAL3    | constant `0x7FC` occurs with several right shifts by `9`                                                                                     |
| HC128    | bit mask `0x3FF` occurs with consecutive right rotations by `23`, `10`, and `8` as well as consecutive right rotations by `7`, `18`, and `3` |
| SALSA20  | string value `expand 32-byte k` occurs                                                                                                       |
| ECC      | ...                                                                                                                                          |
| RSA      | ...                                                                                                                                          |
| AES      | Identifiable by SBox                                                                                                                         |
| DES      | Identifiable by SBox                                                                                                                         |
| Blowfish | Identifiable by SBox                                                                                                                         |
| RC5      | ...                                                                                                                                          |
| TEA      | Uses the nothing-up-my-sleeve-number `0x9E3779B9`.                                                                                           |

## Compression

| Name  | Help                                                                                                                          |
|-------|-------------------------------------------------------------------------------------------------------------------------------|
| APLIB | ...                                                                                                                           |
| BZ2   | ...                                                                                                                           |
| GZip  | ...                                                                                                                           |
| ZLib  | ...                                                                                                                           |
| LZ4   | The upper and lower 4 bit of the first byte of the compressed data are interpreted as different integers and used as a length |
| LZMA  | ...                                                                                                                           |
| ZIP   | ...                                                                                                                           |

## Compiler Optimizations

| Name                | Help         |
|---------------------|--------------|
| `strlen`            | `0x7efefeff` |
| `memset`            | `0x01010101` |
| inverse square root | `0x5f3759df` |
