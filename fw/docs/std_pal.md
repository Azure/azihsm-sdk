# Standard PAL Implementation

**Crates:** `azihsm_fw_hsm_std`, `azihsm_fw_hsm_pal_std`

## Overview

The standard PAL provides a host-native HSM simulation that runs entirely in user-space. It uses an Embassy single-threaded executor for the core logic, a tokio runtime for async crypto, and heap-allocated buffers for key storage. This enables development, testing, and integration without hardware.

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Host Thread (tokio)                            │
│                                                 │
│  StdHsm::io(sqe, pid) ──► async_channel ──►    │
│  StdHsm::part_alloc(pid) ─► ipc_channel ──►    │
│                                                 │
│         ▼ oneshot reply                         │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────┼────────────────────────────┐
│  Embassy Thread    │                            │
│                    ▼                            │
│  poll_io() ──► handle_io() [pool_size = 32]     │
│  ipc_task() ──► part_alloc/free/enable/disable  │
│  run_core() ──► init + cert store + event loop  │
│                                                 │
│  StdHsmPal (all PAL traits)                     │
│    ├── StdIic/StdOic (IO drivers)               │
│    ├── StdGdma (pointer-based DMA)              │
│    ├── KeyVault (heap-allocated per-partition)   │
│    ├── SessionTable (bitmask allocator)          │
│    ├── SharedCertStore (root/devid/alias certs)  │
│    └── OpenSSL crypto (via azihsm_crypto)       │
└─────────────────────────────────────────────────┘
```

## StdHsm — Entry Point

`StdHsm` is the public API. It manages:

- An **Embassy executor** on a dedicated background thread
- An optional **tokio runtime** (owned or caller-provided)
- An **IO submission channel** (`async_channel`, bounded to 31)
- An **IPC channel** for sideband partition commands

### Construction

```rust
// Default: creates its own tokio runtime
let hsm = StdHsm::new();

// With existing tokio runtime
let hsm = StdHsm::with_tokio(handle);

// Builder pattern
let hsm = StdHsm::builder().tokio_handle(handle).build();
```

### IO Submission

```rust
pub async fn io(&self, sqe: HsmSqe, pid: u8, qid: u16, qidx: u16) -> HsmResult<HsmCqe>
```

Constructs an `HsmIoRequest`, sends it through the submit channel, and awaits the per-IO oneshot reply. Automatic backpressure when 31 IOs are in-flight.

### Partition Management

```rust
pub async fn part_alloc(&self, pid: u8, res_mask: u128) -> HsmResult<()>
pub async fn part_free(&self, pid: u8) -> HsmResult<()>
pub async fn part_enable(&self, pid: u8) -> HsmResult<()>
pub async fn part_disable(&self, pid: u8) -> HsmResult<()>
```

Sideband commands sent to the Embassy thread via IPC channel. Each carries a oneshot reply for the result.

## Embassy Task Pool

| Task | Pool Size | Purpose |
|------|-----------|---------|
| `run_core` | 1 | PAL init, cert store init, main event loop |
| `poll_io` | 1 | Receives IOs from submit channel, spawns handlers |
| `handle_io` | 32 | Processes individual IOs (DDI pipeline) |
| `ipc_task` | 1 | Processes partition alloc/free/enable/disable |

## StdHsmPal — PAL Implementation

### IO (StdIic / StdOic)

- **StdIic** (Input IO Controller): receives `HsmIoRequest` from the submit channel, allocates a slot from `BufferPool` (32 slots × 10 KB each = 2 KB fast + 8 KB large per slot).
- **StdOic** (Output IO Controller): sends the CQE back via the per-IO oneshot channel.

### GDMA

Interprets PRP addresses as raw host-process pointers and performs `memcpy`:

```rust
unsafe { ptr::copy_nonoverlapping(src_ptr, dst.as_mut_ptr(), dst.len()) }
```

### Partition Table

A fixed array of 65 `PartitionEntry` structs stored in an `UnsafeCell` on the Embassy thread. Each entry contains:

| Field | Size | Description |
|-------|------|-------------|
| `state` | 1 B | Lifecycle state |
| `res_mask` | 16 B | Resource bitmask |
| `id` | 16 B | Random identity blob |
| `id_key_id` | 2 B | Vault key ID for identity private key |
| `id_pub_key` | 96 B | Raw P-384 public key (x∥y) |
| `leaf_cert` | 2 KB | Cached DER partition leaf certificate |
| `session_table` | 2 B | Bitmask session allocator (8 slots) |
| `vault` | varies | Per-partition `KeyVault` |
| `establish_cred_key_id` | 2 B | Establish-cred key ID (Option) |
| `establish_cred_pub_key` | 96 B | Establish-cred public key |
| `session_enc_key_id` | 2 B | Session encryption key ID (Option) |
| `session_enc_pub_key` | 96 B | Session encryption public key |
| `nonce` | 32 B | Random nonce |

**Thread safety:** The `UnsafeCell` is safe because the Embassy executor is single-threaded — all trait method calls are synchronous and complete without yielding.

### Key Vault (KeyVault)

Heap-allocated per-partition key storage. Each partition gets `res_mask.count_ones()` tables. Keys are stored as `Vec<u8>` with associated `HsmVaultKeyKind`, `HsmVaultKeyAttrs`, and metadata.

### Certificate Store (SharedCertStore)

Generates a 3-certificate chain at PAL init using template-driven X.509 construction:

1. Root CA → self-signed
2. DeviceId CA → signed by Root
3. Alias CA → signed by DeviceId

The Alias private key is cached for signing partition leaf certificates on demand.

### Crypto

All crypto operations delegate to the `azihsm_crypto` crate which wraps OpenSSL on Linux and CNG on Windows:

| Trait | Backend |
|-------|---------|
| HsmRng | `azihsm_crypto::Rng` |
| HsmHash | OpenSSL `EVP_DigestInit/Update/Final` |
| HsmEcc | OpenSSL `EVP_PKEY` ECC operations |
| HsmAes | OpenSSL `EVP_EncryptInit/Update/Final` |
| HsmHmac | OpenSSL `EVP_MAC` |
| HsmRsa | OpenSSL `EVP_PKEY` RSA operations |
| HsmKdf | OpenSSL HKDF / custom KBKDF |

## X.509 Certificate Builder

The `azihsm_crypto::x509_builder` module (used here by the std PAL's `cert` driver) provides template-driven certificate construction:

- Pre-compiled DER templates for root, intermediate, and leaf certificates
- Runtime patching functions that fill in public keys, serial numbers, validity dates, and subject/issuer fields
- Signature assembly from raw (r, s) components into DER-encoded ECDSA signatures

Templates are generated at build time by a companion `gen` crate.

## Shutdown

Dropping `StdHsm` closes both channels, causing Embassy tasks to exit. The Embassy thread is joined to ensure all in-flight IOs complete. If a tokio runtime is owned, it is dropped after the Embassy thread exits.
