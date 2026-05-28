# GetCertChainInfo (Opcode 1108)

**Handler:** `fw/core/lib/src/ddi/get_cert_chain_info.rs`
**Session:** NoSession

## Description

Returns metadata about a certificate chain for a given partition and slot: the number of certificates and a SHA-256 thumbprint of the leaf certificate.

## Request

```rust
pub struct DdiGetCertChainInfoReq {
    pub slot_id: u8,    // Certificate slot (currently only 0 is valid)
}
```

## Response

```rust
pub struct DdiGetCertChainInfoResp<'a> {
    pub num_certs: u8,             // Number of certs in the chain (4 for slot 0)
    pub thumbprint: &'a [u8],      // SHA-256 thumbprint (32 bytes)
}
```

## Encoding Pattern

Simple `encode_resp` — the thumbprint is a fixed 32-byte field.

## Errors

| Error | Cause |
|-------|-------|
| `InvalidArg` | `slot_id` ≠ 0 |
| `InvalidArg` | Partition not allocated |
