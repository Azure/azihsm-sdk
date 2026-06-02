# GetDeviceInfo (Opcode 1003)

**Handler:** `fw/core/lib/src/ddi/get_device_info.rs`
**Session:** NoSession

## Description

Returns device metadata: device kind, number of allocated vault tables for the partition, and FIPS approval status.

## Request

```rust
pub struct DdiGetDeviceInfoReq {}    // Empty body
```

## Response

```rust
pub struct DdiGetDeviceInfoResp {
    pub kind: DdiDeviceKind,     // Physical (hardware) or Virtual (simulator)
    pub tables: u8,              // Number of vault tables (from part_res_count)
    pub fips_approved: bool,
}
```

The fw/core implementation always returns `kind = Physical` and `fips_approved = false`.

## Encoding Pattern

Simple `encode_resp` — all fields are fixed-size primitives.
