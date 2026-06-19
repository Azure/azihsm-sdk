# HsmCrypto — Cryptographic Operations

**Crate:** `azihsm_fw_hsm_pal_traits`
**File:** `fw/pal/traits/src/crypto/`

## Overview

`HsmCrypto` is a composite supertrait that bundles all cryptographic sub-traits. Implementations are typically empty (`impl HsmCrypto for MyPal {}`) since the trait only bundles bounds.

```rust
pub trait HsmCrypto: HsmRng + HsmHash + HsmHmac + HsmAes + HsmEcc + HsmRsa + HsmKdf {}
```

## Sub-traits

### HsmRng — Random Number Generation

**File:** `crypto/rng.rs`

```rust
pub trait HsmRng {
    fn rng(&self, buf: &mut [u8]) -> HsmResult<()>;
}
```

Fills `buf` with cryptographically secure random bytes.

### HsmHash — SHA Digest

**File:** `crypto/hash.rs`

```rust
pub enum HsmHashAlgo { Sha1, Sha256, Sha384, Sha512 }

impl HsmHashAlgo {
    pub fn digest_len(&self) -> usize; // 20, 32, 48, 64
}

pub trait HsmHash {
    async fn hash(&self, algo: HsmHashAlgo, data: &[u8], digest: &mut [u8]) -> HsmResult<()>;
}
```

### HsmEcc — Elliptic Curve Cryptography

**File:** `crypto/ecc.rs`

```rust
pub enum HsmEccCurve { P256, P384, P521 }

impl HsmEccCurve {
    pub fn priv_key_len(&self) -> usize;     // 32, 48, 66
    pub fn pub_key_len(&self) -> usize;      // priv_key_len * 2
    pub fn sig_len(&self) -> usize;          // priv_key_len * 2 (r∥s)
    pub fn secret_len(&self) -> usize;       // priv_key_len
}

pub enum HsmEccPct { None, SignVerify, KeyAgreement }

pub trait HsmEcc {
    async fn ecc_gen_keypair(
        &self, curve: HsmEccCurve, priv_key: Option<&mut [u8]>,
        pub_key: &mut [u8], pct: HsmEccPct,
    ) -> HsmResult<usize>;

    async fn ecc_sign(
        &self, curve: HsmEccCurve, priv_key: &[u8],
        hash: &[u8], signature: &mut [u8],
    ) -> HsmResult<()>;

    async fn ecc_verify(
        &self, curve: HsmEccCurve, pub_key: &[u8],
        hash: &[u8], signature: &[u8],
    ) -> HsmResult<bool>;

    async fn ecdh_derive(
        &self, curve: HsmEccCurve, priv_key: &[u8],
        pub_key: &[u8], secret: &mut [u8],
    ) -> HsmResult<()>;
}
```

Key parameters are `&[u8]` byte slices: raw HSM-format scalar `d` for private keys (32/48/68 bytes, P-521 4-byte aligned), raw x∥y little-endian coordinates for public keys, raw r∥s for signatures.

**PCT (Pairwise Consistency Test):** After key generation, a self-test is performed:
- `SignVerify` — sign + verify a test message
- `KeyAgreement` — ECDH with a test peer

### HsmAes — AES Encrypt/Decrypt

**File:** `crypto/aes.rs`

```rust
pub enum HsmAesMode { Cbc, Gcm }

pub trait HsmAes {
    async fn aes_encrypt(...) -> HsmResult<usize>;
    async fn aes_decrypt(...) -> HsmResult<usize>;
}
```

Supports CBC and GCM modes with 128/192/256-bit keys.

### HsmHmac — HMAC Sign/Verify

**File:** `crypto/hmac.rs`

```rust
pub trait HsmHmac {
    async fn hmac(&self, algo: HsmHashAlgo, key: &[u8], data: &[u8], mac: &mut [u8]) -> HsmResult<()>;
    async fn hmac_verify(&self, algo: HsmHashAlgo, key: &[u8], data: &[u8], mac: &[u8]) -> HsmResult<bool>;
}
```

### HsmRsa — RSA Operations

**File:** `crypto/rsa.rs`

```rust
pub trait HsmRsa {
    async fn rsa_gen_keypair(...) -> HsmResult<usize>;
    async fn rsa_mod_exp(...) -> HsmResult<usize>;
}
```

Supports 2048/3072/4096-bit keys with standard and CRT formats.

### HsmKdf — Key Derivation

**File:** `crypto/kdf.rs`

```rust
pub trait HsmKdf {
    async fn hkdf_derive(...) -> HsmResult<()>;
    async fn kbkdf_counter_hmac_derive(...) -> HsmResult<()>;
}
```

- **HKDF** — HMAC-based Key Derivation Function (RFC 5869)
- **KBKDF** — Key-Based Key Derivation Function in counter mode (NIST SP 800-108)

## Async Design

All crypto operations are `async` to support hardware-backed implementations where the PKA (Public Key Accelerator) engine processes operations asynchronously. On the standard PAL, they complete synchronously via OpenSSL but maintain the async interface for compatibility.
