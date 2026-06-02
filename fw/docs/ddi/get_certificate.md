# GetCertificate (Opcode 1109)

**Handler:** `fw/core/lib/src/ddi/get_certificate.rs`
**Session:** NoSession

## Description

Returns a single DER-encoded certificate from a partition's certificate chain, identified by slot and index.

## Request

```rust
pub struct DdiGetCertificateReq {
    pub slot_id: u8,    // Certificate slot (0)
    pub cert_id: u8,    // Certificate index within the chain (0–3)
}
```

## Response

```rust
pub struct DdiGetCertificateResp<'a> {
    pub certificate: &'a [u8],    // DER-encoded X.509 certificate
}
```

## Encoding Pattern

**Frame-then-fill** — the handler queries the certificate size first, encodes the response frame with a reserved slot, then fills the certificate DER directly into the slot:

```
1. Size query:    pal.get_cert(pid, slot, idx, None) → len
2. Encode frame:  DdiGetCertificateResp::frame(encoder, len) → frame
3. Fill in-place: pal.get_cert(pid, slot, idx, Some(frame.certificate))
```

This avoids an intermediate buffer copy for certificates that can be up to 2 KB.

## Certificate Indices (Slot 0)

| Index | Certificate |
|-------|------------|
| 0 | Root CA (self-signed) |
| 1 | DeviceId CA |
| 2 | Alias CA |
| 3 | Partition Leaf (lazily generated) |

## Errors

| Error | Cause |
|-------|-------|
| `InvalidArg` | `slot_id` ≠ 0 or `cert_id` > 3 |
| `InvalidArg` | Partition not allocated |
