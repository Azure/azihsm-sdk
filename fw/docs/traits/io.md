# HsmIo / HsmIoController — I/O Submission and Completion

**Crate:** `azihsm_fw_hsm_pal_traits`
**File:** `fw/pal/traits/src/io.rs`

## Overview

The I/O traits define how the core receives work items from host controllers and returns completion results. Each IO carries a submission queue entry (SQE) describing the requested operation and a completion queue entry (CQE) populated by the core with the result.

## Constants

```rust
pub const SQE_DWORDS: usize = 16;   // 64 bytes
pub const CQE_DWORDS: usize = 4;    // 16 bytes

pub type HsmSqe = [u32; SQE_DWORDS];
pub type HsmCqe = [u32; CQE_DWORDS];
```

## HsmIo Trait

Represents a single I/O work item — a submission/completion pair.

```rust
pub trait HsmIo {
    fn pid(&self) -> HsmPartId;       // Owning partition
    fn queue_id(&self) -> u16;        // Queue within the controller
    fn queue_idx(&self) -> u16;       // Index within the queue
    fn sqe(&self) -> &HsmSqe;         // Submission queue entry (read-only)
    fn cqe(&mut self) -> &mut HsmCqe; // Completion queue entry (write)
    fn mem(&mut self) -> (&mut [u8], &mut [u8]); // (fast_mem 2KB, large_mem 8KB)
}
```

### Memory Buffers

Each IO owns two memory regions:
- **fast_mem** (2 KB) — scratch memory for the DDI handler (`fmem` parameter)
- **large_mem** (8 KB) — holds both the inbound request and outbound response (`smem` parameter). Split at `src_len.next_multiple_of(4)`: the first half is the padded request, the second half is the response buffer.

## HsmIoController Trait

Manages the IO lifecycle.

```rust
pub trait HsmIoController {
    type Io: HsmIo + Send;

    async fn poll_io(&self) -> HsmResult<Self::Io>;
    async fn complete_io(&self, io: Self::Io) -> HsmResult<()>;
    async fn drop_io(&self, io: Self::Io) -> HsmResult<()>;
}
```

| Method | Description |
|--------|-------------|
| `poll_io()` | Waits for the next IO from the submission queue. Suspends if none available. |
| `complete_io(io)` | Sends the populated CQE back through the completion queue. Consumes the IO. |
| `drop_io(io)` | Discards an IO without sending a CQE. Used when a partition is not enabled. |

## SQE Layout

| DWORD | Field |
|-------|-------|
| DW0 | `cmd`: opcode (10 bits), command set (4), PSDT (2), command ID (16) |
| DW1 | `src.len`: source buffer length |
| DW2–3 | `src.prp1`: source PRP address (lo/hi) |
| DW4–5 | `src.prp2`: source PRP2 address |
| DW6 | `dst.len`: destination buffer length |
| DW7–8 | `dst.prp1`: destination PRP address (lo/hi) |
| DW9–10 | `dst.prp2`: destination PRP2 address |
| DW11 | Session flags: `ctrl` (2 bits), `id_valid` (1), `app_vault_id_valid` (1), `session_closed` (1) |
| DW12 | Session ID (low 16 bits) |
| DW13–15 | Reserved |

## CQE Layout

| DWORD | Field |
|-------|-------|
| DW0 | `dst_len` (16 bits) + session flags (ctrl, id_valid, vault_valid, closed) |
| DW1 | `session_id` (16 bits) + `app_vault_id` (8 bits) |
| DW2 | `sq_head` (16 bits) + `sq_id` (16 bits) |
| DW3 | `cmd_id` (16 bits) + phase (1 bit) + host status (11 bits) |
