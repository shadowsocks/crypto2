# Rust Crypto

[![License](https://img.shields.io/github/license/shadowsocks/crypto2.svg)](https://github.com/shadowsocks/crypto2)
[![Build & Test](https://github.com/shadowsocks/crypto2/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/shadowsocks/crypto2/actions/workflows/rust.yml)
[![crates.io](https://img.shields.io/crates/v/crypto2.svg)](https://crates.io/crates/crypto2)

An all-in-one cryptographic algorithm library in Rust.

## Supported Details

🚧 Interested but not implemented yet ✅ Implemented ❌ Not Interested

### Hardware Acceleration

#### X86/X86-64

- ✅ AES
- ✅ CLMUL
- ❌ SHA（SHA1）
- ✅ SHA（SHA2-256）

#### AArch64

- ✅ AES
- ✅ PMULL
- ❌ SHA1
- ✅ SHA2 （SHA2-256）
- ❌ SHA512 (SHA2-512)
- ❌ SHA3
- ❌ SM3
- ❌ SM4

### Digest Algorithms

- ✅ MD2
- ✅ MD4
- ✅ MD5
- ❌ MD6
- ✅ SHA1
- ✅ SHA2-224
- ✅ SHA2-256
- ✅ SHA2-384
- ✅ SHA2-512
- 🚧 SHA3-256
- 🚧 SHA3-384
- 🚧 SHA3-512
- ✅ SM3
- ✅ BLAKE2b
- ✅ BLAKE2s
- ✅ BLAKE3
- ❌ RIPEMD
- ❌ Whirlpool
- 🚧 GOST

### Symmetric Key Encryption (Block Alogrithms)

- ❌ DES
- ❌ 3DES
- ✅ RC2 (or: ARC2)
- 🚧 RC5
- ❌ RC6
- ✅ AES
- ✅ SM4
- ✅ Camellia
- ✅ ARIA
- 🚧 GOST（Magma、Kuznyechik）
- ❌ Blowfish
- ❌ Twofish
- ❌ Threefish

### Stream Cipher Alogrithms

- ✅ RC4
- ✅ Chacha20
- 🚧 ZUC (in Chinese: 祖冲之算法)

### Asymmetric Cryptographic Algorithm

- 🚧 RSA
- ❌ ED25519
- 🚧 SM2
- 🚧 SM9

### Authenticated Encryption (AE) Algorithms

- ✅ Chacha20Poly1305 (RFC7539)
- ✅ Chacha20Poly1305OpenSSH (chacha20-poly1305@openssh.com)
- ✅ AES-CCM
- ✅ AES-OCB
- ✅ AES-GCM
- ✅ AES-GCM-SIV
- ✅ AES-SIV (AesSivCmac256、AesSivCmac384、AesSivCmac512)

- ✅ CAMELLIA-CCM
- ✅ CAMELLIA-GCM
- ✅ CAMELLIA-GCM-SIV

- ✅ ARIA-CCM
- ✅ ARIA-GCM
- ✅ ARIA-GCM-SIV

- ✅ SM4-CCM
- ✅ SM4-GCM
- ✅ SM4-GCM-SIV

### Encryption Algorithms

- ✅ AES-ECB
- ✅ AES-CBC
- ✅ AES-CFB1
- ✅ AES-CFB8
- ✅ AES-CFB64
- ✅ AES-CFB128
- ✅ AES-OFB
- ✅ AES-CTR

- ✅ CAMELLIA-CBC
- ✅ CAMELLIA-CFB1
- ✅ CAMELLIA-CFB8
- ✅ CAMELLIA-CFB64
- ✅ CAMELLIA-CFB128
- ✅ CAMELLIA-OFB
- ✅ CAMELLIA-CTR

- ✅ ARIA-CBC
- ✅ ARIA-CFB1
- ✅ ARIA-CFB8
- ✅ ARIA-CFB64
- ✅ ARIA-CFB128
- ✅ ARIA-OFB
- ✅ ARIA-CTR

- ✅ SM4-CBC
- ✅ SM4-CFB1
- ✅ SM4-CFB8
- ✅ SM4-CFB64
- ✅ SM4-CFB128
- ✅ SM4-OFB
- ✅ SM4-CTR

### Key Derivation Function (KDF)

- ✅ HKDF
- 🚧 Scrypt
- ❌ PBKDF2

### Message Authentication Code (MAC)

- ✅ HMAC
- ✅ Poly1305
- ✅ GMAC
- ✅ CBC-Mac
- ✅ CMac

### Others

- 🚧 bcrypt
