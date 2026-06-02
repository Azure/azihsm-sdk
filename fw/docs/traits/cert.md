# HsmCertStore — Certificate Chain Retrieval

**Crate:** `azihsm_fw_hsm_pal_traits`
**File:** `fw/pal/traits/src/cert.rs`

## Overview

The certificate store trait provides access to X.509 certificate chains associated with partition/slot pairs. Each partition has one certificate slot (slot 0) containing a 4-certificate chain.

## Types

```rust
pub struct CertChainInfo {
    pub count: u8,            // Number of certificates in the chain
    pub thumbprint: [u8; 32], // SHA-256 thumbprint of the leaf certificate
}
```

## Trait Definition

```rust
pub trait HsmCertStore {
    async fn get_cert_chain_info(
        &self, part_id: HsmPartId, slot_id: u8,
    ) -> HsmResult<CertChainInfo>;

    async fn get_cert(
        &self, part_id: HsmPartId, slot_id: u8, idx: u8, cert: Option<&mut [u8]>,
    ) -> HsmResult<usize>;
}
```

| Method | Description |
|--------|-------------|
| `get_cert_chain_info` | Returns the chain length and leaf thumbprint for the given slot |
| `get_cert` | Reads a single certificate by index. `cert = None` for size query, `Some(buf)` to copy. |

## Certificate Chain (Slot 0)

| Index | Certificate | Scope | Key Usage |
|-------|------------|-------|-----------|
| 0 | Root CA (self-signed) | Shared across all partitions | keyCertSign |
| 1 | DeviceId CA (path_len=1) | Shared | keyCertSign |
| 2 | Alias CA (path_len=0) | Shared | keyCertSign |
| 3 | Partition Leaf | Per-partition, lazily generated | digitalSignature |

### Thumbprint Computation

The leaf thumbprint is computed as:

```
SHA-256( SHA-256(root_cert || deviceid_cert) || SHA-256(alias_cert) || SHA-256(leaf_cert) )
```

### Lazy Leaf Generation

The partition leaf certificate is generated on first access. It contains the partition's identity public key and is signed by the Alias CA private key using ECDSA P-384 with SHA-384.

## Async

Both methods are `async` because leaf certificate generation requires hashing and signing via the PAL's crypto traits.
