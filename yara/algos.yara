rule des
{
    meta:
        description = "Constants from DES implementation"
        author = "@larsborn"
        date = "2020-08-22"
        reference = "https://github.com/tarequeh/DES/blob/master/des.c"
        hash = "0b38ca277bbb042d43bd1f17c4e424e167020883526eb2527ba929b2f0990a8f"
    strings:
        $initial_key_permutaion = {
            39 31 29 21 19 11 09 01 3a 32 2a 22 1a 12 0a 02
            3b 33 2b 23 1b 13 0b 03 3c 34 2c 24 3f 37 2f 27
            1f 17 0f 07 3e 36 2e 26 1e 16 0e 06 3d 35 2d 25
            1d 15 0d 05 1c 14 0c 04
        }
        $initial_message_permutation = {
            3a 32 2a 22 1a 12 0a 02 3c 34 2c 24 1c 14 0c 04
            3e 36 2e 26 1e 16 0e 06 40 38 30 28 20 18 10 08
            39 31 29 21 19 11 09 01 3b 33 2b 23 1b 13 0b 03
            3d 35 2d 25 1d 15 0d 05 3f 37 2f 27 1f 17 0f 07
        }
        $sub_key_permutation = {
            0e 11 0b 18 01 05 03 1c 0f 06 15 0a 17 13 0c 04
            1a 08 10 07 1b 14 0d 02 29 34 1f 25 2f 37 1e 28
            33 2d 21 30 2c 31 27 38 22 35 2e 2a 32 24 1d 20
        }
        $S1 = {
            0e 04 0d 01 02 0f 0b 08 03 0a 06 0c 05 09 00 07
            00 0f 07 04 0e 02 0d 01 0a 06 0c 0b 09 05 03 08
            04 01 0e 08 0d 06 02 0b 0f 0c 09 07 03 0a 05 00
            0f 0c 08 02 04 09 01 07 05 0b 03 0e 0a 00 06 0d
        }
        $S2 = {
            0f 01 08 0e 06 0b 03 04 09 07 02 0d 0c 00 05 0a
            03 0d 04 07 0f 02 08 0e 0c 00 01 0a 06 09 0b 05
            00 0e 07 0b 0a 04 0d 01 05 08 0c 06 09 03 02 0f
            0d 08 0a 01 03 0f 04 02 0b 06 07 0c 00 05 0e 09
        }
        $S3 = {
            0a 00 09 0e 06 03 0f 05 01 0d 0c 07 0b 04 02 08
            0d 07 00 09 03 04 06 0a 02 08 05 0e 0c 0b 0f 01
            0d 06 04 09 08 0f 03 00 0b 01 02 0c 05 0a 0e 07
            01 0a 0d 00 06 09 08 07 04 0f 0e 03 0b 05 02 0c
        }
        $S4 = {
            07 0d 0e 03 00 06 09 0a 01 02 08 05 0b 0c 04 0f
            0d 08 0b 05 06 0f 00 03 04 07 02 0c 01 0a 0e 09
            0a 06 09 00 0c 0b 07 0d 0f 01 03 0e 05 02 08 04
            03 0f 00 06 0a 01 0d 08 09 04 05 0b 0c 07 02 0e
        }
        $S5 = {
            02 0c 04 01 07 0a 0b 06 08 05 03 0f 0d 00 0e 09
            0e 0b 02 0c 04 07 0d 01 05 00 0f 0a 03 09 08 06
            04 02 01 0b 0a 0d 07 08 0f 09 0c 05 06 03 00 0e
            0b 08 0c 07 01 0e 02 0d 06 0f 00 09 0a 04 05 03
        }
        $S6 = {
            0c 01 0a 0f 09 02 06 08 00 0d 03 04 0e 07 05 0b
            0a 0f 04 02 07 0c 09 05 06 01 0d 0e 00 0b 03 08
            09 0e 0f 05 02 08 0c 03 07 00 04 0a 01 0d 0b 06
            04 03 02 0c 09 05 0f 0a 0b 0e 01 07 06 00 08 0d
        }
        $S7 = {
            04 0b 02 0e 0f 00 08 0d 03 0c 09 07 05 0a 06 01
            0d 00 0b 07 04 09 01 0a 0e 03 05 0c 02 0f 08 06
            01 04 0b 0d 0c 03 07 0e 0a 0f 06 08 00 05 09 02
            06 0b 0d 08 01 04 0a 07 09 05 00 0f 0e 02 03 0c
        }
        $S8 = {
            0d 02 08 04 06 0f 0b 01 0a 09 03 0e 05 00 0c 07
            01 0f 0d 08 0a 03 07 04 0c 05 06 0b 00 0e 09 02
            07 0b 04 01 09 0c 0e 02 00 06 0a 0d 0f 03 05 08
            02 01 0e 07 04 0a 08 0d 0f 0c 09 00 03 05 06 0b
        }
        $right_sub_message_permutation = {
            10 07 14 15 1d 0c 1c 11 01 0f 17 1a 05 12 1f 0a
            02 08 18 0e 20 1b 03 09 13 0d 1e 06 16 0b 04 19
        }
        $final_message_permutation =  {
            28 08 30 10 38 18 40 20 27 07 2f 0f 37 17 3f 1f
            26 06 2e 0e 36 16 3e 1e 25 05 2d 0d 35 15 3d 1d
            24 04 2c 0c 34 14 3c 1c 23 03 2b 0b 33 13 3b 1b
            22 02 2a 0a 32 12 3a 1a 21 01 29 09 31 11 39 19
        }
    condition:
        any of them
}

rule aes
{
    meta:
        description = "AES Forward S-box and Reverse S-box"
        author = "@larsborn"
        date = "2020-08-23"
        reference = "https://en.wikipedia.org/wiki/Rijndael_S-box"
    strings:
        $sbox = {
            63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
            ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
            b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15
            04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75
            09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84
            53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf
            d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8
            51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2
            cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73
            60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db
            e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79
            e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08
            ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a
            70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e
            e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df
            8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16
        }
        $reverse_sbox = {
            52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb
            7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb
            54 7b 94 32 a6 c2 23 3d ee 4c 95 0b 42 fa c3 4e
            08 2e a1 66 28 d9 24 b2 76 5b a2 49 6d 8b d1 25
            72 f8 f6 64 86 68 98 16 d4 a4 5c cc 5d 65 b6 92
            6c 70 48 50 fd ed b9 da 5e 15 46 57 a7 8d 9d 84
            90 d8 ab 00 8c bc d3 0a f7 e4 58 05 b8 b3 45 06
            d0 2c 1e 8f ca 3f 0f 02 c1 af bd 03 01 13 8a 6b
            3a 91 11 41 4f 67 dc ea 97 f2 cf ce f0 b4 e6 73
            96 ac 74 22 e7 ad 35 85 e2 f9 37 e8 1c 75 df 6e
            47 f1 1a 71 1d 29 c5 89 6f b7 62 0e aa 18 be 1b
            fc 56 3e 4b c6 d2 79 20 9a db c0 fe 78 cd 5a f4
            1f dd a8 33 88 07 c7 31 b1 12 10 59 27 80 ec 5f
            60 51 7f a9 19 b5 4a 0d 2d e5 7a 9f 93 c9 9c ef
            a0 e0 3b 4d ae 2a f5 b0 c8 eb bb 3c 83 53 99 61
            17 2b 04 7e ba 77 d6 26 e1 69 14 63 55 21 0c 7d
        }
    condition:
        any of them
}

rule base64_alphabet
{
    meta:
        description = "Base64 alphabet string"
        author = "@larsborn"
        date = "2020-08-22"
        reference = "https://en.wikibooks.org/wiki/Algorithm_Implementation/Miscellaneous/Base64"
        hash = "0b38ca277bbb042d43bd1f17c4e424e167020883526eb2527ba929b2f0990a8f"
    strings:
        $base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ld"
    condition:
        all of them
}

rule salsa20
{
    meta:
        description = "Salsa20 stream cipher initial value"
        author = "@larsborn"
        date = "2020-08-23"
        reference = "https://en.wikipedia.org/wiki/Salsa20"
    strings:
        $ = "expand 32-byte k"
    condition:
        all of them
}

rule rand
{
    meta:
        description = "Constant from rand() implementation"
        author = "@larsborn"
        date = "2020-12-13"
        reference = "https://en.wikipedia.org/wiki/Linear_congruential_generator"
    strings:
        $lcg_a = { fd 43 03 00 }
        $lcg_c = { c3 9e 26 00 }
        $lcg_mod = { ff 7f 00 00 }
    condition:
        all of them
}

rule murmur
{
    meta:
        description = "Constants from MurmurHash2"
        author = "@larsborn"
        date = "2021-01-01"
        reference = "https://github.com/abrandoned/murmur2/blob/master/MurmurHash2.c"
    strings:
        $ = { 95 e9 d1 5b }
    condition:
        all of them
}

rule briflz
{
    meta:
        description = "BriefLZ - small fast Lempel-Ziv"
        author = "@larsborn"
        date = "2021-01-03"
        reference = "https://github.com/jibsen/brieflz"
        hash = "f88671a5c98df6ef5ba81cd6a9340673163742050ca08eda64c91f25138efce9"
    strings:
        $name = { 31 7a 6c 62 }
    condition:
        all of them
}

rule rabbit
{
    meta:
        description = "Rabbit - stream cipher submitted to the eSTREAM project in 2005"
        author = "@larsborn"
        date = "2021-02-14"
        reference = "https://de.wikipedia.org/wiki/Rabbit_(Algorithmus)"
        hash = "36d60d54ace6386a5c64f4f9cbf818ae1e9f38352ea6fbd216a87ad1350228ac"
    strings:
        $counter_init_value_1 = { 4d d3 34 4d }
        $counter_init_value_2 = { 34 4d d3 34 }
    condition:
        all of them
}

rule crc32
{
    meta:
        description = "CRC-32 algorithm - constants should be XORed with a state variable which is originally initialized with 0xFFFFFFFF"
        author = "@larsborn"
        date = "2021-05-08"
        reference = "https://en.wikipedia.org/wiki/Cyclic_redundancy_check"
        hash = "de04d2402154f676f757cf1380671f396f3fc9f7dbb683d9461edd2718c4e09d"
    strings:
        $forward_polynomial = { 20 83 b8 ed }
        $reverse_polynomial = { B7 1D C1 04 }
    condition:
        any of them
}

rule sha256
{
    meta:
        description = "SHA256 - Cryptographic hash function belonging to the SHA-2 family"
        author = "@larsborn"
        date = "2021-02-14"
        reference = "https://en.wikipedia.org/wiki/SHA-2"
        hash = "36d60d54ace6386a5c64f4f9cbf818ae1e9f38352ea6fbd216a87ad1350228ac"
    strings:
        $init_hash_value_1 = { 67 e6 09 6a }
        $init_hash_value_2 = { 85 ae 67 bb }
        $init_hash_value_3 = { 72 f3 6e 3c }
        $init_hash_value_4 = { 3a f5 4f a5 }
        $init_hash_value_5 = { 7f 52 0e 51 }
        $init_hash_value_6 = { 8c 68 05 9b }
        $init_hash_value_7 = { ab d9 83 1f }
        $init_hash_value_8 = { 19 cd e0 5b }
    condition:
        all of ($init_hash_value_*)
}

rule sha384
{
    meta:
        description = "SHA256 - Cryptographic hash function belonging to the SHA-2 family"
        author = "@larsborn"
        date = "2021-02-14"
        reference = "https://en.wikipedia.org/wiki/SHA-2"
        hash = "36d60d54ace6386a5c64f4f9cbf818ae1e9f38352ea6fbd216a87ad1350228ac"
    strings:
        $init_hash_value_1 = { d8 9e 05 c1 }
        $init_hash_value_2 = { 07 d5 7c 36 }
        $init_hash_value_3 = { 17 dd 70 30 }
        $init_hash_value_4 = { 39 59 0e f7 }
        $init_hash_value_5 = { 31 0b c0 ff }
        $init_hash_value_6 = { 11 15 58 68 }
        $init_hash_value_7 = { a7 8f f9 64 }
        $init_hash_value_8 = { a4 4f fa be }
    condition:
        all of ($init_hash_value_*)
}

rule deflate
{
    meta:
        description = "Copyright String present in a common implementation of the deflation algorithm"
        author = "@larsborn"
        date = "2021-05-12"
        reference = "https://github.com/GPUOpen-Tools/common_lib_ext_zlib_1.2.8/blob/master/1.2.8/deflate.c"
        hash = "c748284e7cc2868f38d9fff1bf08eaceb600a16b757e2f700ef8fe93f3ac1791"
    strings:
        $copyright_string = "deflate 1.2.8 Copyright 1995-2013 Jean-loup Gailly and Mark Adle"
    condition:
        all of them
}
