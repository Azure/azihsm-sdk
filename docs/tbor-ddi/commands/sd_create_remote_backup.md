<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SdCreateRemoteBackup (Opcode 0x0A)

**Handler:** _Not yet landed — wire schema only._
**Session:** InSession (Crypto Officer)

## Description

Creates a new security domain under the active session's partition from
the caller-supplied unified `PartPolicy`, returning the remote
partition-owner-key backup (`pok_remote_backup`).

## Request

Wire layout: 4-byte header, followed by the TOC entries, then the
variable-length data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4  | `session_id` | `session_id` (inline) | CO session this request is bound to; cross-checked against the SQE-carried session id. |
| 8  | `sender_key` | `key_id` (inline) | Sender key id (`KeyId`, TOC entry type 1). |
| 12 | `mfgr_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Manufacturer certificate-chain descriptors (from the `Evidence` field group). |
| 16 | `owner_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Owner certificate-chain descriptors. |
| 20 | `part_owner_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Partition-owner certificate-chain descriptors. |
| 24 | `evidence` | `buffer` (single `&ReportDescriptor`, 4 B) | Attestation-report (COSE_Sign1) descriptor. |
| 28 | `policy` | `buffer` (fixed 484 B) | Caller-asserted unified `PartPolicy` describing the security domain to create. Length pinned to `PART_POLICY_LEN` (484 B); a wrong length is rejected at decode. |

The four `mfgr_cert_chain` … `evidence` entries are spliced in by the
shared [`Evidence`](../../../fw/core/ddi/tbor/types/src/evidence.rs)
field group; the certificate-chain DER bytes and the COSE_Sign1 report
travel **out of band**, referenced by these `(offset, length)`
descriptors.

### Data section

Carries the packed cert-chain / report descriptors and the 484-byte
`policy` image.

## Response

Wire layout: 8-byte header, followed by the TOC entry, then the data
section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `pok_remote_backup` | `buffer` (fixed 180 B) | Remote partition-owner-key backup, a masked BKS3: an AEAD-GCM-256 envelope (`header(8) ‖ iv(12) ‖ aad(96) ‖ pt(48) ‖ tag(16)`) = `MASKED_SD_LEN` (180 B). |

### Data section

Carries the 180-byte `pok_remote_backup` blob.

## Errors

| Error | Cause |
|---|---|
| `TborInvalidFixedLength` | `policy` is not exactly 484 B (rejected at decode before the handler runs) |
| `SessionNotFound` | `session_id` does not refer to an allocated slot |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/sd_create_remote_backup.rs`
