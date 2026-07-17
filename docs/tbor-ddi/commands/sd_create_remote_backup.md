<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SdCreateRemoteBackup (Opcode 0x0A)

**Handler:** `fw/core/lib/src/ddi/tbor/sd_create_remote_backup.rs`
**Session:** InSession (Crypto Officer)

## Description

Creates a security domain on the partition (manticore `CreateSD`). It
mints a fresh 48-byte BKS3 and a random 32-byte security-domain masking
key (`SDMK`), provisions `SDMK` in the vault as the partition's
`SecurityDomain`-scope masking key, and returns three backups:

- **`pok_remote_backup`** — the fresh BKS3 HPKE-Auth-sealed to the
  *receiver's* SD sealing public key (`RcvrPub`, recovered from the
  receiver's `KeyReport` carried out of band), authenticated by the
  *sender's* SD sealing private key (`SndrPriv`, recovered by unmasking
  `masked_sealing_key`).
- **`pok_local_backup`** — the same BKS3 masked under the partition-local
  masking key (`PartLocalMK`), for on-device (local) recovery of the
  security domain.
- **`sd_mk_backup`** — `SDMK` masked under `SDBMK` (a backup masking key
  derived from BKS3, the platform seeds, and the policy hash), the
  SVN-monotonic backup of the masking key.

The command is **stateful**: it vaults `SDMK` and marks the partition
security-domain-initialized. Every persistent mutation is recorded on the
per-command undo log, so a handler failure — or a failed completion —
rolls the whole command back. It is **one-shot** per partition
incarnation: a second create returns `SdAlreadyInitialized` (the atomic
claim is the race-winner gate). It requires an `Initialized` partition
whose bound policy names this partition as the backing partition.

The receiver attestation **evidence** is validated on-device
([`verify_evidence`](../../../fw/core/evidence/src/lib.rs)): the three
certificate chains (manufacturer / owner / partition-owner) are verified,
the partition-owner chain is anchored to the policy SATA key, and the
attested COSE_Key is recovered as `RcvrPub`.

## Request

Wire layout: 4-byte header, followed by the TOC entries, then the
variable-length data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4  | `session_id` | `session_id` (inline) | CO session this request is bound to; cross-checked against the SQE-carried session id. |
| 8  | `masked_sealing_key` | `buffer` (fixed 180 B) | Sender's masked SD-sealing key (the `masked_key` from `SdSealingKeyGen`), unmasked on-device to recover `SndrPriv`. `MASKED_SEALING_KEY_LEN` (180 B). |
| 12 | `mfgr_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Manufacturer certificate-chain descriptors (from the `Evidence` field group). |
| 16 | `owner_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Owner certificate-chain descriptors. |
| 20 | `part_owner_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Partition-owner certificate-chain descriptors. |
| 24 | `evidence` | `buffer` (single `&ReportDescriptor`, 3 B) | Receiver attestation-report (COSE_Sign1) descriptor. |
| 28 | `policy` | `buffer` (fixed 484 B) | Caller-asserted unified `PartPolicy`. Must match the policy bound at `PartInit` (`SHA-384` re-check) and name this partition as the backing partition (`backup_part_id` = PID, `backup_part_pub_key` = PID public key). Length pinned to `PART_POLICY_LEN` (484 B). |

The four `mfgr_cert_chain` … `evidence` entries are spliced in by the
shared [`Evidence`](../../../fw/core/ddi/tbor/types/src/evidence.rs)
field group.  Each descriptor is `{ index: u8, length: U16 }`: `index`
selects a 16-byte NVMe SGL Data Block descriptor in the **out-of-band**
SGL page (SQE `oob_prp`/`oob_len`), and `length` is the byte count of the
referenced payload.  All three certificate chains **and** the `evidence`
(receiver `KeyReport`) descriptor are consumed: the chains are validated
and the report's COSE_Key is recovered as `RcvrPub`.

### Data section

Carries the 180-byte `masked_sealing_key`, the packed cert-chain / report
descriptors, and the 484-byte `policy` image.  The referenced evidence
payloads (the receiver `KeyReport`) travel out of band.

## Response

Wire layout: 8-byte header, followed by the TOC entry, then the data
section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `pok_remote_backup` | `buffer` (fixed 161 B) | Remote partition-owner-key backup: an HPKE-Auth seal of BKS3 under `DHKemP384Sha384AesGcm256`, `enc(97) ‖ ct(64)` = `POK_REMOTE_BACKUP_LEN` (161 B). |
| 12 | `pok_local_backup` | `buffer` (fixed 180 B) | Local partition-owner-key backup: BKS3 masked under `PartLocalMK`. `MASKED_SD_LEN` (180 B). |
| 16 | `sd_mk_backup` | `buffer` (fixed 164 B) | Security-domain masking-key backup: `SDMK` masked under the derived `SDBMK`. `LOCAL_MK_BACKUP_LEN` (164 B). |

### Data section

Carries the 161-byte `pok_remote_backup` seal, the 180-byte
`pok_local_backup`, and the 164-byte `sd_mk_backup` envelope.

## Errors

| Error | Cause |
|---|---|
| `TborInvalidFixedLength` | `masked_sealing_key` (180 B) or `policy` (484 B) is the wrong length (rejected at decode before the handler runs) |
| `InvalidArg` | Not `Initialized`; missing out-of-band evidence; policy hash mismatch; or the policy does not name this partition as the backing partition |
| `SdAlreadyInitialized` | A security domain is already initialized on this partition incarnation (one-shot gate) |
| `InvalidPermissions` | Not a Crypto-Officer session |
| `UnsupportedKeyScope` | The masked sealing key's scope has no provisioned masking key |
| `UnsupportedKeyType` | The unmasked key is not an `SdSealing` key |
| `SessionNotFound` | `session_id` does not refer to an `Active` slot |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/sd_create_remote_backup.rs`
- Sender flow: [`SdSealingKeyGen`](sd_sealing_key_gen.md) → [`KeyReport`](key_report.md) → `SdCreateRemoteBackup`

