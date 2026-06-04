# HsmPartitionManager — Partition Lifecycle and Identity

**Crate:** `azihsm_fw_hsm_pal_traits`
**File:** `fw/pal/traits/src/part.rs`

## Overview

The partition manager trait provides read-only queries for partition state, identity, internal key material, and nonce. Partition mutations (alloc, free, enable, disable) are handled by sideband commands outside this trait.

## Partition States

```rust
pub enum PartState {
    Unallocated,  // Slot is empty, no resources
    Allocated,    // Resources + identity key pair assigned, not yet operational
    Enabled,      // Fully operational, internal keys + nonce present
    Disabled,     // Internal keys cleared, resources + identity remain
}
```

## Trait Methods

### Partition State and Identity

| Method | Signature | Description |
|--------|-----------|-------------|
| `part_state` | `(pid: HsmPartId) → HsmResult<PartState>` | Current lifecycle state |
| `part_res_count` | `(pid: HsmPartId) → HsmResult<u8>` | Number of allocated vault tables |
| `part_id` | `(pid: HsmPartId) → HsmResult<&[u8]>` | 16-byte opaque identity blob |

### Identity Key (created at `part_alloc`)

| Method | Signature | Description |
|--------|-----------|-------------|
| `part_id_key_id` | `(pid: HsmPartId) → HsmResult<HsmKeyId>` | Vault key ID for the identity ECC-384 private key |
| `part_id_pub_key` | `(pid: HsmPartId, out: Option<&mut [u8]>) → HsmResult<usize>` | Raw public key (x∥y, 96 bytes). `None` = size query. |

### Establish-Credential Encryption Key (created at `part_enable`, one-time use)

| Method | Signature | Description |
|--------|-----------|-------------|
| `part_establish_cred_key_id` | `(pid: HsmPartId) → HsmResult<Option<HsmKeyId>>` | Key ID, or `None` if consumed |
| `part_establish_cred_pub_key` | `(pid: HsmPartId, out: Option<&mut [u8]>) → HsmResult<usize>` | Raw public key. Returns 0 if cleared. |
| `part_clear_establish_cred_key` | `(pid: HsmPartId) → HsmResult<()>` | Delete from vault (one-time-use pattern). Idempotent. |

### Session Encryption Key (created at `part_enable`)

| Method | Signature | Description |
|--------|-----------|-------------|
| `part_session_enc_key_id` | `(pid: HsmPartId) → HsmResult<HsmKeyId>` | Vault key ID |
| `part_session_enc_pub_key` | `(pid: HsmPartId, out: Option<&mut [u8]>) → HsmResult<usize>` | Raw public key |

### Nonce

| Method | Signature | Description |
|--------|-----------|-------------|
| `part_nonce` | `(pid: HsmPartId, out: Option<&mut [u8]>) → HsmResult<usize>` | 32-byte random nonce. `None` = size query. |
| `part_nonce_refresh` | `(pid: HsmPartId) → HsmResult<()>` | Regenerate nonce from RNG |

## Size-Query Pattern

Methods returning variable-length data follow a two-call pattern:

1. **Size query:** `method(pid, None)` → returns the byte length
2. **Copy:** `method(pid, Some(buf))` → copies data into `buf`, returns length

This enables the frame-then-fill encoding pattern where the response frame is pre-encoded with the correct size, then filled in-place.

## Lifecycle Transitions

See [architecture.md](../architecture.md#partition-lifecycle) for the full state machine and what keys/certs are created/destroyed at each transition.
