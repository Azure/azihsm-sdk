<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SdRestoreLocalBackup (Opcode 0x0D)

**Handler:** `fw/core/lib/src/ddi/tbor/sd_restore_local_backup.rs`
**Session:** InSession (Crypto Officer)

## Description

Restores a security domain from its **device-local** backups (manticore
§3.3.9) — the local-reboot recovery path.  Unlike the remote/peer
restores it needs no sender, HPKE, attestation evidence, or out-of-band
data: it unmasks the two host-replayed backups with keys the device
already holds, re-masks them at the current platform identity, and
re-provisions the security domain.  It is **CreateSD in reverse** and
shares that command's provisioning primitives
(`fw/core/lib/src/ddi/tbor/sd_backup.rs`).

Algorithm:

1. Gate to a Crypto-Officer, `Active` session on an `Initialized`
   partition; fail-fast if the SD is already initialized
   (`SdAlreadyInitialized`).
2. Unmask `pok_local_backup` under the partition-local masking key
   (`PartLocalMK`, from `PartFinal`) → **BKS3**.  The blob must be an
   `SdPartitionOwnerSeed` envelope, and its bound SVN must not be newer
   than the current firmware SVN (`SdBackupSvnRollback`).
3. Derive `SDBMK` from BKS3 + the partition `policy_hash`, then unmask
   `sd_mk_backup` under `SDBMK` → **SDMK** (must be an `SdMasking`
   envelope; same anti-rollback check).
4. Re-mask both at the current `{svn, owner}`: `pok_local_backup =
   mask(BKS3, PartLocalMK)` and `sd_mk_backup = mask(SDMK, SDBMK)`.
5. Vault `SDMK` (SecurityDomain scope), record `SD_MK_KEY_ID`, and mark
   the partition SD-initialized — undo-guarded.  BKS3, SDMK, and SDBMK are
   zeroized before returning.

The command is **stateful** (vaults `SDMK`, marks the partition
SD-initialized) and **one-shot** per partition incarnation: a second
create/restore returns `SdAlreadyInitialized`.  Because `pok_local_backup`
is bound to `PartLocalMK`, the realistic recovery sequence after a reboot
is `PartInit` → `PartFinal(prev_local_mk_backup)` (which restores
`PartLocalMK`) → `SdRestoreLocalBackup`.

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
| `InvalidArg` | Partition is not `Initialized` (not finalized) |
| `SdAlreadyInitialized` | A security domain is already initialized on this partition incarnation (one-shot gate) |
| `SdBackupSvnRollback` | A backup's bound SVN is newer than the current firmware SVN (anti-rollback) |
| `UnsupportedKeyType` | A backup envelope is not the expected kind (`SdPartitionOwnerSeed` / `SdMasking`) |
| `AesGcmDecryptTagDoesNotMatch` | A backup blob is tampered or was masked under a different key (unmask tag mismatch) |
| `InvalidPermissions` | Not a Crypto-Officer session |
| `SessionNotFound` | `session_id` does not refer to an `Active` slot |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/sd_restore_local_backup.rs`
- Shared SD-backup mechanics: `fw/core/lib/src/ddi/tbor/sd_backup.rs`
- Producer of the local backups: [`SdCreateRemoteBackup`](sd_create_remote_backup.md)
