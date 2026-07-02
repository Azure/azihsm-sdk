<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SdRestoreLocalBackup (Opcode 0x0D)

**Handler:** _Not yet landed — wire schema only._
**Session:** InSession

## Description

Restores a security domain from its device-local backups: takes the
local partition-owner-key backup (`pok_local_backup`) and the
security-domain masking-key backup (`sd_mk_backup`), and returns the
refreshed local backups of the same.

## Request

Wire layout: 4-byte header, followed by the TOC entries, then the
variable-length data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4  | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| 8  | `pok_local_backup` | `buffer` (fixed 180 B) | Local partition-owner-key backup to restore (a masked BKS3 wrapped under the device-local key) = `MASKED_SD_LEN` (180 B). |
| 12 | `sd_mk_backup` | `buffer` (fixed 164 B) | Security-domain masking-key backup envelope = `LOCAL_MK_BACKUP_LEN` (164 B). |

### Data section

Carries the 180-byte `pok_local_backup` blob and the 164-byte
`sd_mk_backup` envelope.

## Response

Wire layout: 8-byte header, followed by the TOC entries, then the data
section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8  | `pok_local_backup` | `buffer` (fixed 180 B) | Refreshed local partition-owner-key backup, sized as a masked BKS3 = `MASKED_SD_LEN` (180 B). |
| 12 | `sd_mk_backup` | `buffer` (fixed 164 B) | Refreshed security-domain masking-key backup envelope = `LOCAL_MK_BACKUP_LEN` (164 B). |

### Data section

Carries the 180-byte `pok_local_backup` blob and the 164-byte
`sd_mk_backup` envelope.

## Errors

| Error | Cause |
|---|---|
| `TborInvalidFixedLength` | `pok_local_backup` is not exactly 180 B, or `sd_mk_backup` is not exactly 164 B (rejected at decode before the handler runs) |
| `SessionNotFound` | `session_id` does not refer to an allocated slot |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/sd_restore_local_backup.rs`
