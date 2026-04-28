# Azure Integrated HSM Emulator Firmware

## What This Is

The Azure Integrated HSM firmware is a cryptographic command processor. Host software sends binary commands — "generate a key", "sign this data", "open a session" — and the firmware executes them inside a hardware security boundary where key material never leaves protected memory.

This document describes how the firmware is built: the principles behind it, how a command flows from submission to completion, how partitions isolate tenants, and how the system keeps secrets safe. Technical details like crate maps and dependency graphs are at the end for reference.

## The Big Idea: One Core, Many Platforms

The firmware must run on two wildly different targets:

- A **Cortex-M7 microcontroller Emulators** — no heap, no OS, 1 MB of SRAM, and a hardware PKA (Public Key Accelerator) engine that takes milliseconds to complete an ECC signature.
- A **Linux/Windows host** — OpenSSL, heap allocation, multi-threaded runtimes, used for development and integration testing.

The answer is a clean separation: **trait-based abstraction** at the boundary, **100% shared logic** in the core.

```
┌──────────────────────────────────────────────────────┐
│                  HSM Core (no_std)                   │
│    Parsing · Validation · Dispatch · Encoding        │
│                                                      │
│    Exactly the same code on hardware and host.       │
│    Zero platform-specific conditionals.              │
├───────────────── trait boundary ─────────────────────┤
│   PAL: Platform Abstraction Layer (trait definitions)│
├──────────────┬───────────────────────────────────────┤
│  Cortex-M7   │   Standard PAL (host-native)          │
│  SRAM vaults │   Heap vaults, OpenSSL crypto,        │
│  PKA         │      Embassy + tokio                  │
│  DMA         │   memcpy-based DMA                    │
└──────────────┴───────────────────────────────────────┘
```

New platforms are added by implementing the PAL traits — the core doesn't change. The standard PAL is behaviorally identical to hardware from the host's perspective: the same DDI request bytes produce the same response bytes. This means every test written against the simulation is also a valid test for hardware.

## Async Without the FSM Tax

HSM firmware is inherently concurrent. A device handles 32 IOs in flight simultaneously, and every command involves waiting — waiting for DMA transfers, waiting for the crypto engine, waiting for host memory access. The question is how to express that concurrency.

The traditional embedded approach is **explicit finite state machines**: each command is a multi-state FSM that yields at every hardware interaction point and resumes when an interrupt fires. This works, but the cost is severe. A single command like `GetEstablishCredEncryptionKey` becomes a 7-state machine with ~400 lines of boilerplate — begin/end pairs for key generation, PCT validation, and signing, with explicit error rollback at every state transition. Reading the code requires mentally simulating the state machine. Auditing it for security requires proving that every state transition handles every error path. Adding a new feature means touching the FSM scaffolding, the event dispatch table, and the state enum.

Rust's `async/await` eliminates all of this. The same command is a single async function that reads top-to-bottom:

```rust
pub(crate) async fn get_establish_cred_encryption_key<'a, P: HsmPal>(...) -> HsmResult<&'a [u8]> {
    pal.part_establish_cred_key_id(part_id)?.ok_or(HsmError::KeyNotFound)?;

    let pub_key_len = pal.part_establish_cred_pub_key(part_id, None)?;
    let nonce_len = pal.part_nonce(part_id, None)?;

    let frame = DdiGetEstablishCredEncryptionKeyResp::frame(&mut encoder, ...)?;

    pal.part_establish_cred_pub_key(part_id, Some(frame.pub_key.raw))?;
    pal.part_nonce(part_id, Some(frame.nonce))?;

    pal.hash(HsmHashAlgo::Sha384, frame.pub_key.raw, digest).await?;
    pal.ecc_sign(HsmEccCurve::P384, id_priv_key, digest, frame.pub_key_signature).await?;

    Ok(&smem[..total])
}
```

60 lines. No states, no callbacks, no event dispatch. The compiler generates the state machine. The [Embassy](https://embassy.dev) executor drives it cooperatively on a single thread — no preemption, no data races, no mutexes. Each `.await` point is where the hardware would yield, and the executor runs another task in the meantime.

This isn't just cleaner — it's **more auditable**. Security reviewers can read the function linearly and verify that keys are checked before use, errors propagate correctly, and no secret leaks through an unexpected state transition.

## Zero-Copy Response Encoding

Every byte matters on a microcontroller. The 32 concurrent IO slots consume `32 × 10 KB = 320 KB` of SRAM. Traditional serialization builds a struct in memory and then copies it to the output buffer — that intermediate copy wastes scarce memory and adds latency.

The firmware uses a **frame-then-fill** pattern instead:

1. **Pre-encode** all MBOR framing (map headers, field IDs, byte-string markers) into the output buffer
2. **Reserve** mutable `&mut [u8]` slots for variable-length fields
3. **Fill** the slots in-place — crypto engines write signatures directly, PAL calls copy keys directly, DMA controllers write directly

The result: the response is built exactly once, in its final location. No intermediate buffers, no copies.

This pattern is composable. The `MborFrameable` trait and `#[ddi(frame)]` derive attribute let nested structs participate in the pipeline:

```rust
// The DdiPublicKey's raw bytes get their own reserved slot inside the parent frame
#[ddi(id = 1, frame)]
pub pub_key: DdiPublicKey<'a>,
```

See [ddi/codec.md](ddi/codec.md) for the full encoding system.

## `no_std`: Security Through Constraint

The core and PAL traits compile without the standard library — `#![no_std]` with no heap allocator. This isn't just about embedded compatibility; it's a security posture.

No dynamic allocation means:
- **No use-after-free** — there's nothing to free
- **No double-free** — same reason
- **Deterministic memory usage** — stack frames are known at compile time, so the firmware's exact memory footprint is provable
- **No allocation failures at runtime** — the system either compiles or it doesn't

For firmware that handles cryptographic keys, these guarantees matter. The standard PAL relaxes this for development convenience (`Vec`, `Box`), but the code that runs on hardware never touches the heap.

## The Platform Abstraction Layer

The PAL is the seam between "what to do" and "how to do it." The core knows it needs to sign data with an ECC key — the PAL knows whether that means calling OpenSSL or programming a hardware PKA engine. The core knows it needs to copy a response to the host — the PAL knows whether that means a `memcpy` or a DMA transaction through a GDMA controller.

Everything the core needs from the platform is expressed through one root trait, `HsmPal`, which bundles eight capability groups:

### I/O: Getting Work In and Out

The **IO controller** (`HsmIoController`) is how the firmware receives commands. It produces work items — each carrying a 64-byte SQE (Submission Queue Entry) describing the request and a 16-byte CQE (Completion Queue Entry) for the result. The core processes the SQE, populates the CQE, and hands the IO back for completion.

Each IO also owns two memory buffers: a 2 KB fast scratch region (`fmem`) and an 8 KB shared region (`smem`) that holds both the inbound request and the outbound response. This per-IO memory model means 32 concurrent commands need 32 buffer slots — no sharing, no locking, no contention.

The **GDMA controller** (`HsmGdmaController`) handles the actual data movement. Inbound: copy the encoded DDI request from host memory into `smem`. Outbound: copy the encoded DDI response from `smem` back to the host. On hardware this is a real DMA transaction; on the standard PAL it's a pointer-based `memcpy`.

→ [io.md](traits/io.md) · [gdma.md](traits/gdma.md)

### Partitions: Identity and Lifecycle

The **partition manager** (`HsmPartitionManager`) exposes everything the core needs to know about a partition's current state — is it enabled? What's its identity key? What's the current nonce? — without exposing how partitions are stored or managed internally.

The trait follows a consistent **size-query-then-fill** pattern for variable-length data:

```rust
// Step 1: query the size
let len = pal.part_establish_cred_pub_key(part_id, None)?;

// Step 2: fill in-place (e.g., directly into a frame-reserved slot)
pal.part_establish_cred_pub_key(part_id, Some(frame.pub_key.raw))?;
```

This pattern is fundamental to the zero-copy pipeline: the core queries the size to pre-encode the response frame, then fills the reserved slot directly — no intermediate buffer needed.

The **partition lock** (`HsmPartitionLock`) provides a per-partition async mutex. Multiple partitions process commands concurrently, but commands within the same partition are serialized. This is critical for operations like `EstablishCredential` that mutate partition state.

→ [partition.md](traits/partition.md) · [lock.md](traits/lock.md)

### Keys and Sessions

The **vault** (`HsmVault`) is the key store. Keys go in, key IDs come out. The core never sees raw key material unless it explicitly asks — and when it does (e.g., to pass a private key to `ecc_sign`), it gets a borrowed `&[u8]` tied to the vault's lifetime. Keys are classified by kind (ECC P-384, AES-256, HMAC-SHA384, etc.) and governed by attribute bitfields (can this key sign? encrypt? be exported?).

Key creation returns a `VaultKeyGuard` — an RAII guard that deletes the key if dropped without calling `dismiss()`. This provides automatic rollback for multi-step operations: if creating a key pair fails on the second key, the first is cleaned up without explicit error handling.

The **session manager** (`HsmSessionManager`) tracks authenticated user sessions. Each partition supports up to 8 concurrent sessions. Session-scoped keys are automatically deleted when the session closes.

→ [vault.md](traits/vault.md) · [session.md](traits/session.md)

### Certificates

The **cert store** (`HsmCertStore`) serves X.509 certificate chains. The core asks "give me certificate N from slot S on partition P" and gets DER bytes back. The PAL handles generation, caching, and the lazy creation of per-partition leaf certificates.

→ [cert.md](traits/cert.md)

### Cryptography

The **crypto bundle** (`HsmCrypto`) wraps seven sub-traits covering the full range of HSM cryptographic operations:

| Sub-trait | Operations |
|-----------|-----------|
| `HsmRng` | Cryptographically secure random bytes |
| `HsmHash` | SHA-1/256/384/512 digest |
| `HsmEcc` | ECC key generation, signing, verification, ECDH |
| `HsmAes` | AES-CBC/GCM encrypt/decrypt |
| `HsmHmac` | HMAC computation and verification |
| `HsmRsa` | RSA key generation and modular exponentiation |
| `HsmKdf` | HKDF (RFC 5869) and KBKDF (NIST SP 800-108) |

All crypto operations are `async`. On the standard PAL they complete immediately via OpenSSL. On hardware they yield while the PKA engine processes — and the executor runs another command in the meantime. This is the heart of why the architecture is async: a 3ms ECC signature doesn't block the other 31 IOs.

→ [crypto.md](traits/crypto.md)

## How a Command Flows

Here's the complete journey of a DDI command:

```
Host                    StdHsm                    Embassy Thread
─────                   ──────                    ──────────────
StdHsm::io(sqe, pid)
  │
  ├── oneshot channel ──► poll_io() ──► handle_io(io)
  │                                        │
  │                                   ┌────┴────────────────────────────┐
  │                                   │  1. Gate: partition enabled?    │
  │                                   │  2. Populate CQE header         │
  │                                   │  3. handle_op(io)               │
  │                                   │     ├── validate SQE            │
  │                                   │     └── handle_generic_op(io)   │
  │                                   │         ├── Inbound DMA         │
  │                                   │         ├── Decode DDI header   │
  │                                   │         ├── Session validation  │
  │                                   │         ├── DDI dispatch        │
  │                                   │         │   └── handler(...)    │
  │                                   │         └── Outbound DMA        │
  │                                   │  4. Write session fields to CQE │
  │                                   │  5. complete_io(io)             │
  │                                   └─────────────────────────────────┘
  │
  ◄── oneshot reply ────────────────── CQE returned
```

The request and response share a single 4 KB buffer, split at the request boundary:

```
smem (4096 bytes):
┌──────────────────────────┬──────────────────────────┐
│  Request (src_len bytes) │  Response buffer          │
│  (padded to 4-byte align)│  (remaining space)        │
└──────────────────────────┴──────────────────────────┘
 ◄── inbound DMA writes ──► ◄── handler encodes here ──►
                             ◄── outbound DMA reads ────►
```

### Error Model

Errors split into two tiers based on *when* they occur:

1. **Pre-decode** (bad SQE, DMA failure, garbled header) → CQE carries a host status code. No response body. The host knows something went wrong at the transport level.

2. **Post-decode** (invalid arguments, missing keys, wrong session) → A DDI error response is encoded and DMA'd back. CQE status = Success. The host reads the error from the response body, just like a normal response.

This mirrors the hardware's behavior. See [error_model.md](error_model.md) for the full error taxonomy.

### Session Hijack Protection

Every DDI opcode declares a session control kind:

| Kind | Example Operations | Meaning |
|------|-------------------|---------|
| `NoSession` | GetApiRev, GetCertificate, ShaDigest | No session required |
| `Open` | OpenSession | Creates a new session |
| `InSession` | EccSign, AesEncrypt, DeleteKey | Requires an active session |
| `Close` | CloseSession | Terminates a session |

The firmware validates three properties:
1. The SQE session control bits match the opcode's expected kind
2. The control/id_valid flag combination is consistent
3. If a session ID is present, it matches the DDI header

This prevents a malicious host from sending a session-less request for an in-session command — the firmware rejects it before the handler runs.

## Partitions: Isolation by Design

Partitions are the firmware's isolation boundary. Each partition represents a distinct host controller interface with its own identity, key vault, sessions, and certificate chain. A key in partition A is invisible to partition B.

### Lifecycle

```
Unallocated ──► part_alloc ──► Allocated ──► part_enable ──► Enabled
     ▲                              │                           │
     │                              │                      part_disable
     │                              │                           │
     └────── part_free ─────────────┴───────── Disabled ◄───────┘
```

| Transition | What Happens |
|-----------|-------------|
| **Allocate** | Generate an ECC P-384 identity key pair (with PCT self-test), a 16-byte random ID, and assign vault tables. |
| **Enable** | Generate ephemeral ECC P-384 keys for credential and session encryption, plus a 32-byte random nonce. The partition is now ready for DDI commands. |
| **Disable** | Zeroize all ephemeral keys, nonce, vault contents, and sessions. The identity key and resources survive for re-enable. |
| **Free** | Zeroize everything — identity key, ID blob, leaf cert. The slot returns to the pool. |

Every key is explicitly zeroized on destruction — `fill(0)` on buffers, vault delete on IDs. No cryptographic material survives a disable or free.

### Internal Keys

Three internal keys are generated during the partition lifecycle:

| Key | Purpose | Created | One-Time? |
|-----|---------|---------|-----------|
| **Partition Identity** | Signs public keys in responses. Public key is in the leaf certificate. | Allocate | No — lives until free |
| **Establish-Cred Encryption** | ECDH key for initial credential establishment. | Enable | Yes — consumed after `EstablishCredential` |
| **Session Encryption** | ECDH key for session open/reopen. | Enable | No — reusable until disable |

All are ECC P-384 with `internal` + `local` attributes and undergo Pairwise Consistency Tests immediately after generation.

## Certificate Chain

Each partition has a 4-certificate chain (slot 0):

| Index | Certificate | Signed By |
|-------|------------|-----------|
| 0 | Root CA (self-signed) | Self |
| 1 | DeviceId CA | Root |
| 2 | Alias CA | DeviceId |
| 3 | Partition Leaf | Alias |

The first three are shared and generated once at startup. The leaf is per-partition and lazily generated on first access — its public key matches the partition identity key, binding the chain to the partition's cryptographic identity.

The host uses this chain to verify public keys: responses like `GetEstablishCredEncryptionKey` include a signature made with the identity private key, and the leaf certificate proves that key belongs to this device.

## DDI Commands

| Opcode | Command | Session | Doc |
|--------|---------|---------|-----|
| 1002 | [GetApiRev](ddi/get_api_rev.md) | NoSession | Returns min/max API revision |
| 1003 | [GetDeviceInfo](ddi/get_device_info.md) | NoSession | Returns device kind and table count |
| 1101 | [GetEstablishCredEncryptionKey](ddi/get_establish_cred_encryption_key.md) | NoSession | Returns establish-cred public key + nonce + signature |
| 1108 | [GetCertChainInfo](ddi/get_cert_chain_info.md) | NoSession | Returns cert count and leaf thumbprint |
| 1109 | [GetCertificate](ddi/get_certificate.md) | NoSession | Returns a single certificate from the chain |
| 2006 | [ShaDigest](ddi/sha_digest.md) | NoSession | Computes SHA hash of input data |

Every handler follows the same async signature:

```rust
async fn handler<'a, P: HsmPal>(
    hdr: &DdiReqHdr,           // Decoded request header
    decoder: &mut DdiDecoder,   // Ready to decode the body
    part_id: HsmPartId,         // Which partition
    pal: &P,                    // The platform
    fmem: &mut [u8],            // 2 KB scratch (avoids bloating the async future)
    smem: &'a mut [u8],         // Output buffer (slice of the IO's 4 KB region)
) -> HsmResult<&'a [u8]>       // Encoded response (points into smem)
```

Uniform signatures make handlers predictable and composable. The `fmem` scratch buffer keeps intermediate values (like SHA-384 digests) out of the async future's stack frame — important on Cortex-M7 where each of the 32 concurrent tasks must fit in a fixed memory budget.

---

## Appendix: Technical Reference

### PAL Trait Map

| Trait | Purpose | Sync/Async | Doc |
|-------|---------|------------|-----|
| [`HsmPal`](traits/pal.md) | Root supertrait | — | [pal.md](traits/pal.md) |
| [`HsmIoController`](traits/io.md) | I/O submission and completion | Async | [io.md](traits/io.md) |
| [`HsmGdmaController`](traits/gdma.md) | Host ↔ device DMA | Async | [gdma.md](traits/gdma.md) |
| [`HsmPartitionManager`](traits/partition.md) | Partition lifecycle and identity | Sync | [partition.md](traits/partition.md) |
| [`HsmPartitionLock`](traits/lock.md) | Per-partition async mutex | Async | [lock.md](traits/lock.md) |
| [`HsmCertStore`](traits/cert.md) | Certificate chain retrieval | Async | [cert.md](traits/cert.md) |
| [`HsmSessionManager`](traits/session.md) | Session allocation and state | Sync | [session.md](traits/session.md) |
| [`HsmVault`](traits/vault.md) | Key storage and metadata | Sync | [vault.md](traits/vault.md) |
| [`HsmCrypto`](traits/crypto.md) | Crypto (RNG, Hash, ECC, AES, HMAC, RSA, KDF) | Async | [crypto.md](traits/crypto.md) |

The sync/async split is intentional: partition queries, vault lookups, and session management are nanosecond table lookups. DMA, crypto, and certificate operations involve hardware and yield cooperatively.

### Identifier Newtypes

| Type | Wraps | Purpose |
|------|-------|---------|
| `HsmPartId` | `u8` | Partition index (0–64) |
| `HsmKeyId` | `u16` | Vault key slot |
| `HsmSessId` | `u16` | Session slot |

Used consistently across all traits and core — raw integers only at the public API boundary.

### Crate Map

```
fw/
├── pal/traits/          azihsm_fw_hsm_pal_traits    Platform Abstraction Layer trait definitions
├── core/
│   ├── tracing/         azihsm_fw_hsm_core_tracing  Feature-gated logging macros
│   ├── ddi/
│   │   ├── mbor/        azihsm_fw_ddi_mbor          MBOR binary codec (encode/decode/len)
│   │   ├── derive/      azihsm_fw_ddi_derive        #[derive(Ddi)] proc macro
│   │   ├── types/       azihsm_fw_ddi_types         DDI request/response type definitions
│   │   └── lib/         azihsm_fw_ddi               DDI encoder/decoder facade
│   └── lib/             azihsm_fw_hsm_core          Core application logic (IO pipeline, DDI dispatch)
└── plat/std/
    ├── x509/            azihsm_fw_hsm_std_x509      X.509 certificate template builder
    ├── pal/             azihsm_fw_hsm_pal_std        Standard PAL implementation (host-native)
    └── lib/             azihsm_fw_hsm_std            StdHsm entry point (Embassy executor + tokio)
```

### Dependency Graph

```
azihsm_fw_hsm_std
  └── azihsm_fw_hsm_core
  │     └── azihsm_fw_ddi (facade)
  │     │     ├── azihsm_fw_ddi_mbor
  │     │     └── azihsm_fw_ddi_types
  │     │           └── azihsm_fw_ddi_derive (proc-macro)
  │     └── azihsm_fw_hsm_pal_traits
  └── azihsm_fw_hsm_pal_std
        ├── azihsm_fw_hsm_pal_traits
        └── azihsm_fw_hsm_std_x509
```

Both `azihsm_fw_hsm_core` and `azihsm_fw_hsm_pal_std` depend on `azihsm_fw_hsm_pal_traits` — but the core only uses it as a trait bound (`P: HsmPal`) while the PAL provides the concrete implementation. The core never depends on platform-specific code.

The DDI codec is split into four crates:
- **`mbor`** — wire format primitives, independent of DDI semantics
- **`derive`** — proc macro (build-time only, keeps `syn`/`quote` out of runtime)
- **`types`** — DDI request/response structs and opcodes (the "schema")
- **`lib`** — facade re-exporting encoder/decoder for the core
