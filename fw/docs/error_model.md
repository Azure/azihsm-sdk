# Error Model

**Files:** `fw/pal/traits/src/error.rs`, `fw/core/lib/src/error.rs`

## Overview

The HSM firmware uses a two-tier error model matching the hardware specification. Errors are classified based on *when* they occur in the IO pipeline.

## HsmError — DDI-Level Errors

`HsmError` is an `open_enum` over `u32` with ~200 named variants. It is the universal error type across the PAL and core.

```rust
pub type HsmResult<T> = Result<T, HsmError>;
```

### Key Error Categories

| Range | Category | Examples |
|-------|----------|---------|
| `0x08700001–0x0870000F` | General | `InvalidArg`, `NotEnoughSpace`, `KeyNotFound` |
| `0x08700010–0x0870002F` | Crypto | `RsaEncryptFailed`, `EccSignError`, `AesDecryptFailed` |
| `0x08700050–0x0870006F` | Vault/Session | `VaultIsFull`, `SessionNotFound`, `LoginFailed` |
| `0x087000A0–0x087000AF` | PCT Validation | `PctValidationEstablishCredEncKeyFailed` |
| `0x087000C0–0x087000DF` | Partition | `CredentialsNotEstablished`, `PartitionAlreadyProvisioned` |
| Special | DDI Protocol | `UnsupportedCmd`, `UnsupportedRevision`, `DdiDecodeFailed`, `DdiEncodeFailed` |

## Two-Tier IO Error Handling

### Tier 1: Pre-Decode Errors (OpError)

Errors that occur before the DDI request body is decoded: SQE validation, inbound DMA, header decode.

```rust
pub struct OpError {
    pub err: HsmError,      // Internal error code (logged)
    pub status: u16,        // HostStatus code (written to CQE DW3)
}
```

**Result:** CQE gets a non-zero host status code. No DDI response body is written.

### HostStatus Codes

| Code | Name | Cause |
|------|------|-------|
| `0x000` | `SUCCESS` | No error |
| `0x0C0` | `INVALID_PSDT` | SQE PSDT field ≠ 0 |
| `0x0C1` | `INVALID_SRC_LEN` | Source length = 0 or > 4096 |
| `0x0C2` | `INVALID_DST_LEN` | Destination length = 0 or > 4096 |
| `0x0C3` | `INVALID_SRC_PRP` | Source PRP not 4K-aligned |
| `0x0C4` | `INVALID_DST_PRP` | Destination PRP not 4K-aligned |
| `0x0C5` | `INVALID_COMMAND_OPCODE` | Unknown SQE opcode |
| `0x181` | `DMA_TXN_ERROR` | DMA copy failed |
| `0x182` | `REQ_HDR_DECODE_ERR` | MBOR header decode failed |
| `0x1FF` | `INTERNAL_ERROR` | Catch-all |

### Tier 2: Post-Decode Errors (DdiErrResp)

Errors that occur after successful header decode: session validation, DDI command execution.

**Result:** A `DdiErrResp` (empty body + error status in `DdiRespHdr`) is encoded into the response buffer and DMA'd to the host. CQE status = `SUCCESS` — the host reads the error from the DDI response body.

```rust
// Encoded as: DdiRespHdr { op, status: error_code, ... } + DdiErrResp {}
fn encode_ddi_err(op: DdiOp, status: HsmError, smem: &mut [u8]) -> HsmResult<usize>
```

## Error Flow in handle_mbor_op

```
SQE validation ────► OpError → CQE host status (no body)
        │
   Inbound DMA ────► OpError → CQE host status (no body)
        │
   Header decode ──► OpError → CQE host status (no body)
        │
   Session validate ► DdiErrResp → CQE Success + error in body
        │
   DDI dispatch ────► DdiErrResp → CQE Success + error in body
        │
   Handler success ─► DdiResp → CQE Success + response in body
```
