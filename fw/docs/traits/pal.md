# HsmPal — Root Platform Abstraction Trait

**Crate:** `azihsm_fw_hsm_pal_traits`
**File:** `fw/pal/traits/src/pal.rs`

## Overview

`HsmPal` is the root supertrait that all HSM platform implementations must satisfy. It bundles every PAL sub-trait into a single bound so that the core logic (`Hsm<P: HsmPal>`) can access all platform capabilities through one generic parameter.

## Definition

```rust
pub trait HsmPal:
    HsmIoController
    + HsmGdmaController
    + HsmPartitionManager
    + HsmPartitionLock
    + HsmCertStore
    + HsmSessionManager
    + HsmVault
    + HsmCrypto
    + Default
{
    fn init(&self);
    async fn run(&self);
    fn deinit(&self);
}
```

## Lifecycle Methods

| Method | Description |
|--------|-------------|
| `init()` | One-time hardware or driver setup. Called before `run()`. |
| `run()` | Async entry point for the platform's main event loop. Returns on completion or fatal error. |
| `deinit()` | Cleanup after `run()` returns. Releases resources. |

## Sub-trait Hierarchy

```
HsmPal
 ├── HsmIoController        — I/O submission queue and completion
 ├── HsmGdmaController      — Host ↔ device DMA memory copies
 ├── HsmPartitionManager    — Partition lifecycle queries
 ├── HsmPartitionLock       — Per-partition async mutex for DDI handlers
 ├── HsmCertStore           — Certificate chain retrieval
 ├── HsmSessionManager      — Session allocation and state tracking
 ├── HsmVault               — Cryptographic key storage
 └── HsmCrypto              — Cryptographic operations
      ├── HsmRng            — Random number generation
      ├── HsmHash           — SHA digest computation
      ├── HsmHmac           — HMAC sign/verify
      ├── HsmAes            — AES encrypt/decrypt
      ├── HsmEcc            — ECC keygen/sign/verify/ECDH
      ├── HsmRsa            — RSA keygen/modular exponentiation
      └── HsmKdf            — HKDF and KBKDF key derivation
```

## Identifier Newtypes

Three transparent newtypes in `lib.rs` prevent accidental mixing of partition, key, and session indices:

| Type | Wraps | Conversions | Purpose |
|------|-------|-------------|---------|
| `HsmPartId` | `u8` | `From<u8>`, `Into<u8>` | Partition index (0–64) |
| `HsmKeyId` | `u16` | `From<u16>`, `Into<u16>` | Vault key slot |
| `HsmSessId` | `u16` | `From<u16>`, `Into<u16>` | Session slot |

## Implementations

| Platform | Crate | Description |
|----------|-------|-------------|
| Host-native (std) | `azihsm_fw_hsm_pal_std` | Heap-allocated buffers, OpenSSL crypto, Embassy + tokio |
| Cortex-M7 (planned) | `azihsm_fw_uno_pal` | On-chip SRAM, hardware PKA engine |
