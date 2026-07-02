<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SdCreatePeerBackup (Opcode 0x0E)

**Handler:** _Not yet landed — wire schema only._
**Session:** InSession

## Description

Creates a peer-transferable backup of a security domain: takes the local
partition-owner-key backup (`pok_local_backup`), re-masks it for the
destination peer named by `dst_evidence` under the named sealing key, and
returns the peer backup (`pok_peer_backup`).

## Request

Wire layout: 4-byte header, followed by the TOC entries, then the
variable-length data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4  | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| 8  | `sealing_key_id` | `key_id` (inline) | Vault id (`HsmKeyId`) of the sealing key the `pok_local_backup` is bound to (`KeyId`, TOC entry type 1). |
| 12 | `mfgr_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Destination manufacturer certificate-chain descriptors (from the `dst_evidence` field group). |
| 16 | `owner_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Destination owner certificate-chain descriptors. |
| 20 | `part_owner_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Destination partition-owner certificate-chain descriptors. |
| 24 | `evidence` | `buffer` (single `&ReportDescriptor`, 4 B) | Destination attestation-report (COSE_Sign1) descriptor. |
| 28 | `policy` | `buffer` (fixed 484 B) | Caller-asserted unified `PartPolicy` describing the security domain being backed up. Length pinned to `PART_POLICY_LEN` (484 B); a wrong length is rejected at decode. |
| 32 | `pok_local_backup` | `buffer` (fixed 180 B) | Local partition-owner-key backup to re-mask (a masked BKS3 wrapped under the device-local key) = `MASKED_SD_LEN` (180 B). |

The four `mfgr_cert_chain` … `evidence` entries are spliced in by the
shared [`Evidence`](../../../fw/core/ddi/tbor/types/src/evidence.rs)
field group (`dst_evidence`); the certificate-chain DER bytes and the
COSE_Sign1 report travel **out of band**, referenced by these
`(offset, length)` descriptors.

### Data section

Carries the packed destination cert-chain and report descriptors, the
484-byte `policy` image, and the 180-byte `pok_local_backup` blob.

## Response

Wire layout: 8-byte header, followed by the TOC entry, then the data
section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `pok_peer_backup` | `buffer` (fixed 180 B) | Partition-owner-key backup re-masked for the destination peer, sized as a masked BKS3 = `MASKED_SD_LEN` (180 B). |

### Data section

Carries the 180-byte `pok_peer_backup` blob.

## Errors

| Error | Cause |
|---|---|
| `TborInvalidFixedLength` | `policy` is not exactly 484 B, or `pok_local_backup` is not exactly 180 B (rejected at decode before the handler runs) |
| `SessionNotFound` | `session_id` does not refer to an allocated slot |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/sd_create_peer_backup.rs`
