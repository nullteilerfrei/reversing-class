# Identification Help for Known Algorithms

## Cryptography

Identification:

| Name     | Help                                                                                                                                         |
|----------|----------------------------------------------------------------------------------------------------------------------------------------------|
| AES      | Identifiable by SBox                                                                                                                         |
| Blowfish | Identifiable by SBox                                                                                                                         |
| DES      | Identifiable by SBox                                                                                                                         |
| ECC      | ...                                                                                                                                          |
| HC128    | bit mask `0x3FF` occurs with consecutive right rotations by `23`, `10`, and `8` as well as consecutive right rotations by `7`, `18`, and `3` |
| RC4      | a buffer is initialized with incrementing integer values                                                                                     |
| RC5      | ...                                                                                                                                          |
| RSA      | ...                                                                                                                                          |
| Rabbit   | ...                                                                                                                                          |
| SALSA20  | string value `expand 32-byte k` occurs                                                                                                       |
| SEAL3    | constant `0x7FC` occurs with several right shifts by `9`                                                                                     |
| TEA      | Uses the nothing-up-my-sleeve-number `0x9E3779B9`.                                                                                           |

Samples:

| Name     | SHA-256 Hash                                                       | Remark                     |
|----------|--------------------------------------------------------------------|----------------------------|
| AES      | `ed675db1e7c93526141d40ba969bdc5bbdfd013932aaf1e644c66db66ff008e0` | Might be a PyXie loader    |
| Blowfish | ...                                                                |                            |
| DES      | `0b38ca277bbb042d43bd1f17c4e424e167020883526eb2527ba929b2f0990a8f` | Zlob                       |
| ECC      | `de04d2402154f676f757cf1380671f396f3fc9f7dbb683d9461edd2718c4e09d` | NetWalker                  |
| HC128    | `e9d2bc32a003fb158e9774cb25f1b6ff81aca9e9b2651eef80753fd64a8233f0` | Maze Packer                |
| RC4      | `ef6a96bf68ec54d78f4f4cd304acc6718f9dfe398f368bc1e5b127bd746302f2` | REvil                      |
| RC5      | ...                                                                |                            |
| RSA      | ...                                                                |                            |
| Rabbit   | ...                                                                |                            |
| SALSA20  | `de04d2402154f676f757cf1380671f396f3fc9f7dbb683d9461edd2718c4e09d` | NetWalker                  |
| SEAL3    | `06df4a5fda733594ce5225118badf6747890ec3a37fe2c59854a54622a809814` | At `00409200`; FlawedAmmyy |
| TEA      | ...                                                                |                            |

## Compression

Identification:

| Name    | Help                                                                                                                          |
|---------|-------------------------------------------------------------------------------------------------------------------------------|
| APLIB   | `0x7D00` and `0x500`                                                                                                          |
| BZ2     | ...                                                                                                                           |
| GZip    | ...                                                                                                                           |
| ZLib    | ...                                                                                                                           |
| LZ4     | The upper and lower 4 bit of the first byte of the compressed data are interpreted as different integers and used as a length |
| LZMA    | ...                                                                                                                           |
| ZIP     | ...                                                                                                                           |
| BriefLZ | ...                                                                                                                           |

Samples:

| Name    | SHA-256 Hash                                                       | Remark           | Function    |
|---------|--------------------------------------------------------------------|------------------|-------------|
| APLIB   | `ed356e738dea161f113c33be8e418d52a468c6ff67c0fd779096331cd12152d5` | Dipper Shellcode | `000000940` |
| BZ2     | ...                                                                |                  |             |
| GZip    | ...                                                                |                  |             |
| ZLib    | ...                                                                |                  |             |
| LZ4     | `0fe796e1b7db725115a7de7ee8a56540f838305356b5de2f24de0883300e2c23` | DPRK Malz        | `180004eb0` |
| LZMA    | ...                                                                |                  |             |
| ZIP     | `c0c234444ffcaedd23abb4a56062f08fe032289c5208f26c441c4a674fa118b4` | WannaCry Stage 2 |             |
| BriefLZ | `b3be07bc668c5671f2ebbe4204eb76ee6710e03b46dc899bf03bfdf0b5d6dfbf` | ChillyVanilly    |             |
| QuickLZ | ...                                                                |                  |             |

## Compiler Optimizations

| Name                | Help         |
|---------------------|--------------|
| `strlen`            | `0x7efefeff` |
| `memset`            | `0x01010101` |
| inverse square root | `0x5f3759df` |
