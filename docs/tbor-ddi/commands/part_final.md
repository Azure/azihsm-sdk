<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# PartFinal (Opcode 0x08)

**Handler:** _Not yet landed — wire schema only._
**Session:** InSession (Crypto Officer)

## Description

Finalizes a partition after [`PartInit`](./part_init.md) by installing
the POTA-endorsed PTA certificate chain and deriving the partition's
local masking keys.  The caller re-supplies the unified `PartPolicy`
(so the handler can recover `POTAPubKey` for cert-chain validation),
the PTA cert-chain descriptor list (pointing into the **side-band**
data buffer), and an optional prior `local_mk` backup to restore.  It
returns the current `local_mk` backup envelope, which the host persists
and replays as `prev_local_mk_backup` on subsequent launches.

## Request

Wire layout: 4-byte header, followed by the TOC entries, then the
variable-length data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4  | `session_id` | `session_id` (inline) | CO session this request is bound to; cross-checked against the SQE-carried session id. |
| 8  | `part_policy` | `buffer` (offset/len) | Caller-asserted unified `PartPolicy` re-supplied from `PartInit`. Length pinned to 484 B. The handler verifies `SHA-384(part_policy)` against the stored policy hash. |
| 12 | `cert_descriptors` | `buffer` (offset/len) | Packed list of `CertDescriptor` entries `(offset: u16, length: u16)`, each 4 B little-endian, locating the DER certificates of the PTA chain in the **side-band** data buffer (the certificate bytes are transferred out of band). 1–8 entries (a non-zero multiple of 4 B, up to 32 B). |
| 16 | `prev_local_mk_backup` | `buffer` (offset/len) | Optional previously-generated `local_mk` backup envelope to restore. An **empty** field means absent; when present it is exactly 164 B. |

### Data section

Carries the `part_policy` (484 B), the packed `cert_descriptors`, and
the optional `prev_local_mk_backup` envelope.  The PTA certificate
bytes themselves are **not** in the TBOR message — `cert_descriptors`
points into a separate side-band buffer.

`CertDescriptor` elements are `Unaligned` (alignment 1, little-endian
`U16` fields), so the typed slice is borrowed zero-copy with no
alignment padding.

## Response

Wire layout: 8-byte header, followed by the TOC entry, then the data
section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `local_mk_backup` | `buffer` (offset/len) | Current `local_mk` backup envelope (`CurrPartLocalKMKBackup`). Always exactly 164 B. |

### Data section

Carries the 164-byte `local_mk_backup` envelope.

## Errors

| Error | Cause |
|---|---|
| `TborInvalidFixedLength` | `part_policy` not 484 B, `cert_descriptors` not a 1–8-element multiple of 4 B, or a present `prev_local_mk_backup` not 164 B |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/part_final.rs`
- Partition setup: [`part_init.md`](./part_init.md)
