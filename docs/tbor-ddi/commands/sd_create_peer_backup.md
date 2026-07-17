<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SdCreatePeerBackup (Opcode 0x0E)

**Handler:** `fw/core/lib/src/ddi/tbor/sd_create_peer_backup.rs`
**Session:** InSession (Crypto Officer)

## Description

Creates a **peer-transferable** backup of a security domain (manticore
§3.3.10): it recovers BKS3 from the caller's device-local backup
(`pok_local_backup`) and HPKE-Auth-seals it to a destination peer — named
by `dst_evidence` and authenticated by the sender's own masked SD-sealing
key — returning the peer backup (`pok_peer_backup`).

It is **[`SdCreateRemoteBackup`](sd_create_remote_backup.md)'s
HPKE-Auth-seal front-end over a recovered (not freshly minted) BKS3**,
sharing the BKS3-recovery primitive with
[`SdRestoreLocalBackup`](sd_restore_local_backup.md)
(`fw/core/lib/src/ddi/tbor/sd_backup.rs`).

Algorithm:

1. Gate to a Crypto-Officer, `Active` session on an `Initialized`
   partition (`PartLocalMK` and the policy hash are bound by `PartFinal`).
   Unlike the restores this is **not** one-shot and does not touch `SDMK`,
   so it neither requires nor sets the SD-initialized flag — a rebooted
   partition can clone to a peer after `PartFinal` without first restoring
   the SD locally.
2. Bind the caller-supplied `policy` to the partition's fixed `policy_hash`,
   then require its `allow_peer_cloning` flag (`SdPeerCloningNotAllowed`).
3. Verify the **destination** peer evidence against that policy: the
   manufacturer / owner / partition-owner certificate chains are validated
   and anchored to the policy `SATA` key, the report's v2 `policy_hash`
   must equal `SHA-384(policy)`, and its attested COSE_Key is recovered as
   **`RcvrPub`**.
4. Unmask `masked_sealing_key` under its scope's masking key → the sender's
   private HPKE key **`SndrPriv`** (must be an `SdSealing` key), and derive
   `SndrPub` on-device.
5. Recover **BKS3** from `pok_local_backup` (unmask under `PartLocalMK`;
   must be an `SdPartitionOwnerSeed` envelope whose bound SVN is not newer
   than the current firmware SVN).
6. HPKE-Auth-seal BKS3 to `RcvrPub` with `SndrPriv` as the
   sender-authentication key, returning `pok_peer_backup` (161 B).
   `SndrPriv` and BKS3 are zeroized before returning.

The command is **stateless**: no vault writes, no partition-state
mutation, no undo log.

## Request

Wire layout: 4-byte header, followed by the TOC entries, then the
variable-length data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4  | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| 8  | `masked_sealing_key` | `buffer` (fixed 180 B) | The **sender's** masked SD-sealing key (from [`SdSealingKeyGen`](sd_sealing_key_gen.md)); unmasked on-device to recover `SndrPriv`. Length pinned to `MASKED_SEALING_KEY_LEN` (180 B). Never a vault handle. |
| 12 | `policy` | `buffer` (fixed 484 B) | Caller-asserted unified `PartPolicy` describing the security domain being backed up. Length pinned to `PART_POLICY_LEN` (484 B); its SHA-384 digest must equal the partition's bound `policy_hash` and the receiver report's v2 `policy_hash`. |
| 16 | `mfgr_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Destination manufacturer certificate-chain descriptors (from the `dst_evidence` field group). |
| 20 | `owner_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Destination owner certificate-chain descriptors. |
| 24 | `part_owner_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Destination partition-owner certificate-chain descriptors. |
| 28 | `evidence` | `buffer` (single `&ReportDescriptor`, 4 B) | Destination attestation-report (COSE_Sign1) descriptor. |
| 32 | `pok_local_backup` | `buffer` (fixed 180 B) | Device-local partition-owner-key backup (a masked BKS3 wrapped under `PartLocalMK`) from which BKS3 is recovered = `MASKED_SD_LEN` (180 B). |

The four `mfgr_cert_chain` … `evidence` entries are spliced in by the
shared [`Evidence`](../../../fw/core/ddi/tbor/types/src/evidence.rs)
field group (`dst_evidence`); the certificate-chain DER bytes and the
COSE_Sign1 report travel **out of band**, referenced by these
`(offset, length)` descriptors.

### Data section

Carries the 180-byte `masked_sealing_key`, the 484-byte `policy` image,
the packed destination cert-chain and report descriptors, and the 180-byte
`pok_local_backup` blob.

## Response

Wire layout: 8-byte header, followed by the TOC entries, then the data
section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8  | `pok_peer_backup` | `buffer` (fixed 161 B) | Peer backup: an HPKE-Auth seal of BKS3 to the destination peer = `POK_REMOTE_BACKUP_LEN` (161 B). |

### Data section

Carries the 161-byte `pok_peer_backup` seal.

## Errors

| Error | Cause |
|---|---|
| `TborInvalidFixedLength` | `masked_sealing_key` ≠ 180 B, `policy` ≠ 484 B, or `pok_local_backup` ≠ 180 B (rejected at decode before the handler runs) |
| `InvalidArg` | Partition is not `Initialized` (not finalized); the policy `SATA` key is not P-384; the destination report's `policy_hash` ≠ `SHA-384(policy)`; or the missing OOB evidence page |
| `SdPeerCloningNotAllowed` | The partition's policy does not set `allow_peer_cloning` |
| `SdBackupSvnRollback` | `pok_local_backup`'s bound SVN is newer than the current firmware SVN (anti-rollback) |
| `UnsupportedKeyType` | `masked_sealing_key` is not an `SdSealing` key, or `pok_local_backup` is not an `SdPartitionOwnerSeed` envelope |
| `AesGcmDecryptTagDoesNotMatch` | `pok_local_backup` is tampered or was masked under a different `PartLocalMK` (unmask tag mismatch) |
| Evidence errors | The destination certificate chains fail validation or do not anchor to the policy `SATA` key, or the report signature is invalid |
| `InvalidPermissions` | Not a Crypto-Officer session |
| `SessionNotFound` | `session_id` does not refer to an `Active` slot |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/sd_create_peer_backup.rs`
- Shared SD-backup mechanics: `fw/core/lib/src/ddi/tbor/sd_backup.rs`
- Consumer of the peer backup: [`SdRestorePeerBackup`](sd_restore_peer_backup.md)
- Producer of the local backup: [`SdCreateRemoteBackup`](sd_create_remote_backup.md)
