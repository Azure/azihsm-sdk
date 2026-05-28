# DDI Codec — MBOR Encoding and Frame Pattern

**Crates:** `azihsm_fw_ddi_mbor`, `azihsm_fw_ddi_derive`, `azihsm_fw_ddi_types`

## Overview

DDI commands are serialized using MBOR (AZIHSM Binary Object Representation), a compact binary format based on CBOR-like principles. Every DDI message is an outer `Map(2)` containing a header (key 0) and a data body (key 1).

## Wire Format

```
Map(2)
  key=0 → DdiReqHdr / DdiRespHdr (map)
  key=1 → Command-specific request/response (map)
```

### MBOR Primitives

| Marker | Type | Encoding |
|--------|------|----------|
| `0xA0 \| count` | Map | 1 byte: marker + field count (max 31) |
| `0x18` | u8 | `[0x18, value]` |
| `0x19` | u16 | `[0x19, hi, lo]` (big-endian) |
| `0x1A` | u32 | `[0x1A, b3, b2, b1, b0]` |
| `0x1B` | u64 | `[0x1B, ...]` (8 bytes) |
| `0x14` | bool | `[0x14]` (true) or `[0x15]` (false) |
| `0x80 \| pad` | bytes | `[0x80\|pad, len_hi, len_lo, pad_bytes..., data...]` |

Byte arrays with `max_len` are 4-byte aligned via padding. Fixed-size byte arrays (`len`) have no padding.

## Derive Macro: `#[derive(Ddi)]`

The `Ddi` derive macro generates four trait implementations for `#[ddi(map)]` structs:

| Trait | Purpose |
|-------|---------|
| `MborEncode` | Serialize to MBOR bytes |
| `MborDecode` | Deserialize from MBOR bytes |
| `MborLen` | Compute encoded length without writing |
| Frame (conditional) | Frame-then-fill for zero-copy encoding |

### Field Attributes

| Attribute | Description |
|-----------|-------------|
| `#[ddi(id = N)]` | MBOR field ID (required, must be sequential) |
| `#[ddi(len = N)]` | Fixed-size byte slice — no padding |
| `#[ddi(max_len = N)]` | Variable-size byte slice — 4-byte padded |
| `#[ddi(frame)]` | Opt-in nested frame-then-fill encoding |

### Field Classification

| Rust Type | Kind | Encode | Frame |
|-----------|------|--------|-------|
| `u8`, `u16`, `u32`, `u64`, `bool` | Normal | Inline | Passed by value |
| Nested `#[ddi(map)]` struct | Normal | Inline via `MborEncode` | Inline (or delegated if `#[ddi(frame)]`) |
| `[u8; N]` | Array | `MborByteSlice` | Passed by value |
| `&'a [u8]` | Slice | `MborByteSlice` / `MborPaddedByteSlice` | Reserved `&mut [u8]` slot |
| `Option<T>` | Optional | Skipped if `None` | Excluded from frame |

## Frame-Then-Fill Pattern

For responses with variable-length byte fields, the frame pattern avoids intermediate copies by:

1. **Pre-encoding** all MBOR structure (map headers, field IDs, byte-string markers, padding)
2. **Reserving** mutable `&mut [u8]` slots for byte-slice fields via `MborEncoder::encode_reserve`
3. **Returning** a Frame struct whose fields point into the reserved slots
4. **Filling** the slots in-place (DMA write, PAL copy, or crypto output)

### Example

```rust
// Type definition
#[derive(Ddi)]
#[ddi(map)]
pub struct DdiShaDigestResp<'a> {
    #[ddi(id = 1, max_len = 64)]
    pub digest: &'a [u8],
}

// Handler usage
let resp_hdr = ddi::success_hdr(hdr, DdiOp::ShaDigest);
let mut encoder = ddi::encode_resp_hdr(&resp_hdr, smem)?;
let frame = DdiShaDigestResp::frame(&mut encoder, digest_len)?;
let total = encoder.position();

// Fill in-place — zero copy
pal.hash(algo, body.msg, frame.digest).await?;
Ok(&smem[..total])
```

### Generated Types

For a struct with frameable fields, the derive generates:

- **`<Struct>Frame<'a>`** — frame struct with `&'a mut [u8]` per slice field
- **`<Struct>FrameParams`** — parameter bundle (lengths for slices, values for primitives)
- **`impl MborFrameable`** — trait enabling nested frame delegation

## MborFrameable Trait

Enables nested structs to participate in a parent's frame:

```rust
pub trait MborFrameable {
    type FrameParams;
    type Frame<'a>;

    fn mbor_frame<'a>(
        encoder: &mut MborEncoder<'a>,
        params: Self::FrameParams,
    ) -> Result<Self::Frame<'a>, MborEncodeError>;
}
```

When a parent field is annotated with `#[ddi(frame)]`, the parent's `frame()` delegates to the child's `MborFrameable::mbor_frame()` instead of encoding the child inline. The child's frame slots are exposed in the parent's Frame struct.

### Example: Nested DdiPublicKey

```rust
#[derive(Ddi)]
#[ddi(map)]
pub struct DdiGetEstablishCredEncryptionKeyResp<'a> {
    #[ddi(id = 1, frame)]              // ← delegates to DdiPublicKey's frame
    pub pub_key: DdiPublicKey<'a>,
    #[ddi(id = 2, len = 32)]
    pub nonce: &'a [u8],
    #[ddi(id = 3, max_len = 192)]
    pub pub_key_signature: &'a [u8],
}

// Usage: all three fields are filled in-place
let frame = DdiGetEstablishCredEncryptionKeyResp::frame(
    &mut encoder,
    DdiPublicKeyFrameParams { raw_len: 96, key_kind: DdiKeyType::Ecc384Public },
    nonce_len,
    sig_len,
)?;
pal.part_establish_cred_pub_key(pid, Some(frame.pub_key.raw))?;
pal.part_nonce(pid, Some(frame.nonce))?;
pal.ecc_sign(..., frame.pub_key_signature).await?;
```

## DDI Header Types

```rust
pub struct DdiReqHdr {
    pub rev: Option<DdiApiRev>,   // API revision
    pub op: DdiOp,                // Opcode
    pub sess_id: Option<u16>,     // Session ID (for InSession commands)
}

pub struct DdiRespHdr {
    pub rev: Option<DdiApiRev>,
    pub op: DdiOp,
    pub sess_id: Option<u16>,
    pub status: DdiStatus,        // 0 = Success
    pub fips_approved: bool,
}
```

## Response Encoding Helpers

The core provides two encoding paths:

| Helper | Use Case |
|--------|----------|
| `encode_resp(hdr, data, smem)` | Simple responses — header + data encoded in one shot |
| `encode_resp_hdr(hdr, smem)` → `Struct::frame(encoder, ...)` | Frame-then-fill — header first, then frame with reserved slots |
