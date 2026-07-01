<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SdResealBackup (Opcode 0x0B)

**Handler:** _Not yet landed — wire schema only._
**Session:** InSession

## Description

Re-masks an existing security-domain blob (`pok_remote_backup`) for a new
recipient: unmasks the caller-supplied `pok_remote_backup` under the named
sealing key and re-masks it under the destination, returning a freshly
resealed `pok_remote_backup`.

## Request

Wire layout: 4-byte header, followed by the TOC entries, then the
variable-length data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4  | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| 8  | `sealing_key_handle` | `key_id` (inline) | Vault id (`HsmKeyId`) of the sealing key the source `pok_remote_backup` is bound to (`KeyId`, TOC entry type 1). |
| 12 | `policy` | `buffer` (fixed 484 B) | Caller-asserted unified `PartPolicy` describing the security domain being resealed. Length pinned to `PART_POLICY_LEN` (484 B); a wrong length is rejected at decode. |
| 16 | `mfgr_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Source manufacturer certificate-chain descriptors (from the `src_evidence` field group). |
| 20 | `owner_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Source owner certificate-chain descriptors. |
| 24 | `part_owner_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Source partition-owner certificate-chain descriptors. |
| 28 | `evidence` | `buffer` (single `&ReportDescriptor`, 4 B) | Source attestation-report (COSE_Sign1) descriptor. |
| 32 | `mfgr_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Destination manufacturer certificate-chain descriptors (from the `dest_evidence` field group). |
| 36 | `owner_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Destination owner certificate-chain descriptors. |
| 40 | `part_owner_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Destination partition-owner certificate-chain descriptors. |
| 44 | `evidence` | `buffer` (single `&ReportDescriptor`, 4 B) | Destination attestation-report (COSE_Sign1) descriptor. |
| 48 | `pok_remote_backup` | `buffer` (fixed 180 B) | Source masked security-domain blob to reseal, sized as a masked BKS3 = `MASKED_SD_LEN` (180 B). |

The two four-entry descriptor blocks are spliced in by the shared
[`Evidence`](../../../fw/core/ddi/tbor/types/src/evidence.rs) field group
(`src_evidence` then `dest_evidence`); the certificate-chain DER bytes
and the COSE_Sign1 reports travel **out of band**, referenced by these
`(offset, length)` descriptors.

### Data section

Carries the packed source / destination cert-chain and report
descriptors, the 484-byte `policy` image, and the 180-byte source
`pok_remote_backup` blob.

## Response

Wire layout: 8-byte header, followed by the TOC entry, then the data
section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `pok_remote_backup` | `buffer` (fixed 180 B) | Resealed security-domain blob, sized as a masked BKS3: an AEAD-GCM-256 envelope (`header(8) ‖ iv(12) ‖ aad(96) ‖ pt(48) ‖ tag(16)`) = `MASKED_SD_LEN` (180 B). |

### Data section

Carries the 180-byte resealed `pok_remote_backup` blob.

## Errors

| Error | Cause |
|---|---|
| `TborInvalidFixedLength` | `policy` is not exactly 484 B, or `pok_remote_backup` is not exactly 180 B (rejected at decode before the handler runs) |
| `SessionNotFound` | `session_id` does not refer to an allocated slot |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/sd_reseal_backup.rs`
