# HsmCrypto — Cryptographic Operations

**Crate:** `azihsm_fw_hsm_pal_traits`
**File:** `fw/pal/traits/src/crypto/`

## Overview

`HsmCrypto` is a composite supertrait that bundles all cryptographic sub-traits. Implementations are typically empty (`impl HsmCrypto for MyPal {}`) since the trait only bundles bounds.

```rust
pub trait HsmCrypto: HsmRng + HsmHash + HsmHmac + HsmAes + HsmEcc + HsmRsa + HsmKdf {}
```

> **Note — signatures are simplified.** The trait signatures shown throughout
> this document use plain `&[u8]` / `&mut [u8]` for readability. In the actual
> firmware PAL traits (`fw/pal/traits/src/crypto/`) the byte-buffer parameters
> are DMA-capable [`DmaBuf`] buffers (`&DmaBuf` / `&mut DmaBuf`), **not** plain
> slices, and most methods also take an `io: &impl HsmIo` context. The `DmaBuf`
> requirement is load-bearing: the Uno PKA/SHA/AES engines DMA directly from
> these buffers, so non-DMA memory (e.g. DTCM stack/heap) is **not** acceptable
> on the hardware path. Read the buffers below as "raw byte buffers,
> conceptually" but `DmaBuf` in practice.

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

Key parameters are raw byte buffers (DMA-backed `DmaBuf` in the firmware PAL traits — see the note above), all in HSM-native **little-endian** (PKA operand order): raw HSM-format scalar `d` for private keys (32/48/68 bytes, P-521 4-byte aligned), raw x∥y coordinates for public keys, and raw r∥s for signatures (each component little-endian).

Byte order also governs the digest and the ECDH secret:
- `ecc_sign` / `ecc_verify` take the message `hash` in PKA **little-endian** — a *full byte reversal* of the natural big-endian digest, which is exactly what `HsmHash::hash(.., big_endian = false)` produces. Callers either hash with `big_endian = false`, or hash big-endian and then reverse the digest.
- `ecdh_derive` writes `secret` as the shared x-coordinate in **little-endian**. Consumers that need big-endian — e.g. an openssl-matching HKDF, or HPKE/DHKEM per RFC 9180 — must reverse it to big-endian themselves.

**PCT (Pairwise Consistency Test):** A PCT checks that a private key and its public key belong together. `ecc_gen_keypair` and `ecc_gen_keypair_from_root` run the PCT that `pct` selects before they return a key; `HsmEccPct::None` runs none. Callers choose the PCT from the key's use: `SignVerify` for a signing key and `KeyAgreement` for any other ECC key.

- `SignVerify` — hash a fixed message, sign the digest with the private key, and verify the signature with the public key.
- `KeyAgreement` — run ECDH in both directions with a fixed test key pair: the new private key with the test public key, and the test private key with the new public key. Both must produce the same shared secret (the X coordinate).

`HsmRsaPct` selects an RSA PCT the same way:

- `SignVerify` — hash a fixed message, raise the digest to the private exponent (`mod_exp_priv`), raise the result to the public exponent (`mod_exp_pub`), and compare the result with the digest.
- `EncryptDecrypt` — raise a fixed value to the public exponent, raise the result to the private exponent, and compare the result with the value.

The Uno PAL runs every PCT with its PCT crate, `azihsm_fw_uno_pct` (`fw/plat/uno/fw/crates/pct`):

- The Uno PAL runs the generation PCTs, and `EncryptDecrypt` on the partition's unwrapping key. When one of these PCTs fails, the PAL doesn't return an error; the module enters the [FIPS error state](../error_model.md#fips-error-state).
- `ecc_priv_der_to_vault` and `rsa_priv_der_to_vault`, which convert an imported key, also take a `pct`. The import handlers pick it from the imported key's use with `ecc_pct_for` and `rsa_pct_for` (`azihsm_fw_hsm_key_decode`), and the Uno PAL runs it on the converted key. A failed PCT rejects the import with an error.
- Before an imported ECC key's PCT, the Uno PAL checks the key's structure, whatever `pct` selects: its PKCS#8 encoding must carry an uncompressed public key, right after the private key, that matches the private key.
- The std PAL runs no PCTs and no structure checks. It ignores `pct`.

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
