<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SdRestorePeerBackup (Opcode 0x0F)

**Handler:** `fw/core/lib/src/ddi/tbor/sd_restore_peer_backup.rs`
**Session:** InSession (Crypto Officer)

## Description

Restores a security domain from a **peer** backup (manticore §3.3.11) —
the peer-cloning recovery path.  It is
**[`SdRestoreRemoteBackup`](sd_restore_remote_backup.md) plus a
peer-cloning policy gate**: it HPKE-Auth-opens the caller-supplied
`pok_peer_backup` (an HPKE seal of BKS3) with the receiver's masked
SD-sealing key — authenticated by the sender peer's attested key —
recovers `SDMK` from `prev_sd_mk_backup`, and returns the device-local
backups so the security domain can afterwards be restored locally without
the peer.

The provisioning half is shared with the local and remote restores
(`fw/core/lib/src/ddi/tbor/sd_backup.rs::reprovision_sd_from_bks3`).

Algorithm:

1. Gate to a Crypto-Officer, `Active` session on an `Initialized`
   partition; fail-fast if the SD is already initialized
   (`SdAlreadyInitialized`).
2. Bind the caller-supplied `policy` to the partition's fixed `policy_hash`,
   then require its `allow_peer_cloning` flag (`SdPeerCloningNotAllowed`).
3. Verify the **sender** peer evidence against that policy: the cert chains
   are validated and anchored to the policy `SATA` key, the report's v2
   `policy_hash` must equal `SHA-384(policy)`, and its attested COSE_Key is
   recovered as **`SndrPub`**.
4. Unmask `masked_sealing_key` under its scope's masking key → the
   receiver's private HPKE key **`RcvrPriv`** (must be an `SdSealing`
   key), and derive `RcvrPub` on-device.
5. HPKE-Auth-open `pok_peer_backup` (`sk_r = RcvrPriv`, sender-auth
   `SndrPub`) → **BKS3**.
6. Recover `SDMK` from `prev_sd_mk_backup` (SDMK masked under the SDBMK
   derived from BKS3 + the partition `policy_hash`), re-mask both backups
   at the current `{svn, owner}`, vault `SDMK` (SecurityDomain scope),
   record `SD_MK_KEY_ID`, and mark the partition SD-initialized —
   undo-guarded.  `RcvrPriv`, BKS3, SDMK, and SDBMK are zeroized before
   returning.

The command is **stateful** (vaults `SDMK`, marks the partition
SD-initialized) and **one-shot** per partition incarnation: a second
create/restore returns `SdAlreadyInitialized`.  Because `masked_sealing_key`
is bound to the device masking key, the realistic recovery sequence after
a reboot is `PartInit` → `PartFinal(prev_local_mk_backup)` (which restores
`PartLocalMK`) → `SdRestorePeerBackup`.

## Request

Wire layout: 4-byte header, followed by the TOC entries, then the
variable-length data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4  | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| 8  | `masked_sealing_key` | `buffer` (fixed 180 B) | The **receiver's** masked SD-sealing key (from [`SdSealingKeyGen`](sd_sealing_key_gen.md)); unmasked on-device to recover `RcvrPriv`. Length pinned to `MASKED_SEALING_KEY_LEN` (180 B). Never a vault handle. |
| 12 | `policy` | `buffer` (fixed 484 B) | Caller-asserted unified `PartPolicy` describing the security domain being restored. Length pinned to `PART_POLICY_LEN` (484 B); its SHA-384 digest must equal the partition's bound `policy_hash` and each report's v2 `policy_hash`. |
| 16 | `mfgr_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Source peer manufacturer certificate-chain descriptors (from the `src_evidence` field group). |
| 20 | `owner_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Source peer owner certificate-chain descriptors. |
| 24 | `part_owner_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Source peer partition-owner certificate-chain descriptors. |
| 28 | `evidence` | `buffer` (single `&ReportDescriptor`, 4 B) | Source peer attestation-report (COSE_Sign1) descriptor. |
| 32 | `pok_peer_backup` | `buffer` (fixed 161 B) | Peer backup to restore: an HPKE-Auth seal of BKS3 = `POK_REMOTE_BACKUP_LEN` (161 B). |
| 36 | `prev_sd_mk_backup` | `buffer` (fixed 164 B) | Previous security-domain masking-key backup (SDMK masked under the derived SDBMK) = `SD_MK_BACKUP_LEN` (164 B); `SDMK` is recovered from it. |

The four `mfgr_cert_chain` … `evidence` entries are spliced in by the
shared [`Evidence`](../../../fw/core/ddi/tbor/types/src/evidence.rs)
field group (`src_evidence`); the certificate-chain DER bytes and the
COSE_Sign1 report travel **out of band**, referenced by these
`(offset, length)` descriptors.

### Data section

Carries the 180-byte `masked_sealing_key`, the 484-byte `policy` image,
the packed source cert-chain and report descriptors, the 161-byte
`pok_peer_backup` seal, and the 164-byte `prev_sd_mk_backup` envelope.

## Response

Wire layout: 8-byte header, followed by the TOC entries, then the data
section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8  | `pok_local_backup` | `buffer` (fixed 180 B) | Local partition-owner-key backup (BKS3 re-masked under `PartLocalMK`), sized as a masked BKS3 = `MASKED_SD_LEN` (180 B). |
| 12 | `sd_mk_backup` | `buffer` (fixed 164 B) | Refreshed security-domain masking-key backup envelope (SDMK re-masked under SDBMK) = `SD_MK_BACKUP_LEN` (164 B). |

### Data section

Carries the 180-byte `pok_local_backup` blob and the 164-byte
`sd_mk_backup` envelope.

## Errors

| Error | Cause |
|---|---|
| `TborInvalidFixedLength` | `masked_sealing_key` ≠ 180 B, `policy` ≠ 484 B, `pok_peer_backup` ≠ 161 B, or `prev_sd_mk_backup` ≠ 164 B (rejected at decode before the handler runs) |
| `InvalidArg` | Partition is not `Initialized` (not finalized); the policy `SATA` key is not P-384; the sender report's `policy_hash` ≠ `SHA-384(policy)`; or the opened backup is not a 48-byte BKS3 |
| `SdAlreadyInitialized` | A security domain is already initialized on this partition incarnation (one-shot gate) |
| `SdPeerCloningNotAllowed` | The partition's policy does not set `allow_peer_cloning` |
| `SdBackupSvnRollback` | A backup's bound SVN is newer than the current firmware SVN (anti-rollback) |
| `UnsupportedKeyType` | `masked_sealing_key` is not an `SdSealing` key, or `prev_sd_mk_backup` is not an `SdMasking` envelope |
| `AesGcmDecryptTagDoesNotMatch` | A backup blob is tampered or was masked/sealed under a different key (unmask / HPKE-open tag mismatch) |
| Evidence errors | The sender certificate chains fail validation or do not anchor to the policy `SATA` key, or the report signature is invalid |
| `InvalidPermissions` | Not a Crypto-Officer session |
| `SessionNotFound` | `session_id` does not refer to an `Active` slot |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/sd_restore_peer_backup.rs`
- Shared SD-backup mechanics: `fw/core/lib/src/ddi/tbor/sd_backup.rs`
- Remote recovery path: [`SdRestoreRemoteBackup`](sd_restore_remote_backup.md)
- Local recovery path: [`SdRestoreLocalBackup`](sd_restore_local_backup.md)
- Producer of the peer backup: [`SdCreatePeerBackup`](sd_create_peer_backup.md)
