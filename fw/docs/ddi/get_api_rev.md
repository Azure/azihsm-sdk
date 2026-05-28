# GetApiRev (Opcode 1002)

**Handler:** `fw/core/lib/src/ddi/get_api_rev.rs`
**Session:** NoSession

## Description

Returns the minimum and maximum API revisions supported by the device. Used by the host to negotiate a compatible protocol version.

## Request

```rust
pub struct DdiGetApiRevReq {}    // Empty body
```

## Response

```rust
pub struct DdiGetApiRevResp {
    pub min: DdiApiRev,    // { major: u32, minor: u32 }
    pub max: DdiApiRev,
}
```

Currently returns `min = max = { major: 1, minor: 0 }`.

## Encoding Pattern

Simple `encode_resp` — all fields are fixed-size primitives.

## Revision Validation

If the request includes `rev: Some(...)`, the handler validates it against the supported range. Unsupported revisions return `HsmError::UnsupportedRevision`.
