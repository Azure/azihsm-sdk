# HsmGdmaController — DMA Memory Copies

**Crate:** `azihsm_fw_hsm_pal_traits`
**File:** `fw/pal/traits/src/gdma.rs`

## Overview

The GDMA (General DMA) controller trait provides memory copy operations between host memory and HSM-local buffers. On hardware, this interfaces with the GDMA peripheral; on the standard PAL, it uses direct pointer-based copies.

## Types

```rust
#[derive(Debug, Clone, Copy, Default)]
pub struct HsmDmaAddr {
    pub lo: u32,  // Lower 32 bits
    pub hi: u32,  // Upper 32 bits
}
```

## Trait Definition

```rust
pub trait HsmGdmaController {
    async fn copy_mem(&self, src: &[u8], dst: &mut [u8]) -> HsmResult<()>;

    async fn copy_mem_from_host(
        &self, part_id: HsmPartId, src: HsmDmaAddr, dst: &mut [u8], prp: bool,
    ) -> HsmResult<()>;

    async fn copy_mem_to_host(
        &self, part_id: HsmPartId, src: &[u8], dst: HsmDmaAddr, prp: bool,
    ) -> HsmResult<()>;
}
```

| Method | Direction | Description |
|--------|-----------|-------------|
| `copy_mem` | Local → Local | Copy between HSM-local buffers |
| `copy_mem_from_host` | Host → HSM | Inbound DMA: read request data from host PRP address |
| `copy_mem_to_host` | HSM → Host | Outbound DMA: write response data to host PRP address |

### Parameters

- **`part_id`** — Partition identifier for the host controller interface.
- **`prp`** — If `true`, interpret the address as a PRP (Physical Region Page) pair; if `false`, as an SGL (Scatter-Gather List) descriptor.

## Usage in IO Pipeline

The core's `handle_mbor_op` (and TBOR sibling `handle_tbor_op`) calls GDMA twice:

1. **Inbound DMA** (Phase 1): `copy_mem_from_host(part_id, sqe.src_prp1, smem)` — reads the encoded DDI request from host memory into the IO buffer.
2. **Outbound DMA** (Phase 3): `copy_mem_to_host(part_id, response, sqe.dst_prp1)` — writes the encoded DDI response back to host memory.
