<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SdRestorePeerBackup (Opcode 0x0F)

**Handler:** _Not yet landed — wire schema only._
**Session:** InSession

## Description

Restores a security domain from a peer backup: unmasks the
caller-supplied peer partition-owner-key backup (`pok_peer_backup`, a
masked BKS3) under the named sealing key, re-wraps it under the
device-local key, and returns the local backup (`pok_local_backup`)
together with the security-domain masking-key backup (`sd_mk_backup`).

## Request

Wire layout: 4-byte header, followed by the TOC entries, then the
variable-length data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4  | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| 8  | `sealing_key_id` | `key_id` (inline) | Vault id (`HsmKeyId`) of the sealing key the `pok_peer_backup` is bound to (`KeyId`, TOC entry type 1). |
| 12 | `mfgr_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Source manufacturer certificate-chain descriptors (from the `src_evidence` field group). |
| 16 | `owner_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Source owner certificate-chain descriptors. |
| 20 | `part_owner_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Source partition-owner certificate-chain descriptors. |
| 24 | `evidence` | `buffer` (single `&ReportDescriptor`, 4 B) | Source attestation-report (COSE_Sign1) descriptor. |
| 28 | `policy` | `buffer` (fixed 484 B) | Caller-asserted unified `PartPolicy` describing the security domain being restored. Length pinned to `PART_POLICY_LEN` (484 B); a wrong length is rejected at decode. |
| 32 | `pok_peer_backup` | `buffer` (fixed 180 B) | Peer partition-owner-key backup to restore (a masked BKS3) = `MASKED_SD_LEN` (180 B). |
| 36 | `sd_mk_backup` | `buffer` (fixed 164 B) | Security-domain masking-key backup envelope = `LOCAL_MK_BACKUP_LEN` (164 B). |

The four `mfgr_cert_chain` … `evidence` entries are spliced in by the
shared [`Evidence`](../../../fw/core/ddi/tbor/types/src/evidence.rs)
field group (`src_evidence`); the certificate-chain DER bytes and the
COSE_Sign1 report travel **out of band**, referenced by these
`(offset, length)` descriptors.

### Data section

Carries the packed source cert-chain and report descriptors, the
484-byte `policy` image, the 180-byte `pok_peer_backup` blob, and the
164-byte `sd_mk_backup` envelope.

## Response

Wire layout: 8-byte header, followed by the TOC entries, then the data
section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8  | `pok_local_backup` | `buffer` (fixed 180 B) | Partition-owner-key backup re-wrapped under the device-local key, sized as a masked BKS3 = `MASKED_SD_LEN` (180 B). |
| 12 | `sd_mk_backup` | `buffer` (fixed 164 B) | Security-domain masking-key backup envelope = `LOCAL_MK_BACKUP_LEN` (164 B). |

### Data section

Carries the 180-byte `pok_local_backup` blob and the 164-byte
`sd_mk_backup` envelope.

## Errors

| Error | Cause |
|---|---|
| `TborInvalidFixedLength` | `policy` is not exactly 484 B, `pok_peer_backup` is not exactly 180 B, or `sd_mk_backup` is not exactly 164 B (rejected at decode before the handler runs) |
| `SessionNotFound` | `session_id` does not refer to an allocated slot |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/sd_restore_peer_backup.rs`
