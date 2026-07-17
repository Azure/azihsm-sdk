<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SdResealRemoteBackup (Opcode 0x0B)

**Handler:** `fw/core/lib/src/ddi/tbor/sd_reseal_remote_backup.rs`
**Session:** InSession (Crypto Officer)

## Description

Reseals a security-domain **remote backup** from a source recipient to a
destination recipient (manticore §3.3.7 Reseal), run by a Sealing
Authority.  The caller supplies the source backup (`src_remote_backup`,
an HPKE-Auth seal of a 48-byte BKS3) together with the *receiver's*
masked SD-sealing key (`masked_sealing_key`, unmasked on-device to
recover the receiver private key `RcvrPriv`).

The handler HPKE-Auth-**opens** `src_remote_backup` with `RcvrPriv`
(recovering the BKS3), authenticated by the source *sender's* public key
(`SndrPub`, from `src_evidence`); then HPKE-Auth-**reseals** that same
BKS3 to the destination *receiver's* public key (`DstRcvrPub`, from
`dest_evidence`), using the same `RcvrPriv` as the sender-authentication
key ("for simplicity, the same HPKE private key" — manticore).  The
result is returned as `dst_remote_backup`.

The command is **stateless** — nothing is persisted (no vault writes, no
undo log).  It requires an `Initialized` partition (the SD masking keys
are provisioned by `PartFinal`).

Both attestation **evidences** are validated on-device
([`verify_evidence`](../../../fw/core/evidence/src/lib.rs)): each one's
three certificate chains (manufacturer / owner / partition-owner) are
verified and anchored to the **request** policy's SATA key, and each
report's v2 `policy_hash` must equal `SHA-384(policy)`.  This binds the
source and destination to the same policy (whose digest covers the POTA
key).  The attested COSE_Keys are recovered as `SndrPub` (source sender)
and `DstRcvrPub` (destination receiver).  `BKS3` and `RcvrPriv` are
zeroized before returning on every path.

## Request

Wire layout: 4-byte header, followed by the TOC entries, then the
variable-length data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4  | `session_id` | `session_id` (inline) | CO session this request is bound to; cross-checked against the SQE-carried session id. |
| 8  | `masked_sealing_key` | `buffer` (fixed 180 B) | Receiver's masked SD-sealing key (the `masked_key` from `SdSealingKeyGen`), unmasked on-device to recover `RcvrPriv`. The same key both opens the source and authenticates the reseal; never a vault handle. `MASKED_SEALING_KEY_LEN` (180 B). |
| 12 | `policy` | `buffer` (fixed 484 B) | Caller-asserted unified `PartPolicy` the source and destination must share. Its `SHA-384` digest is checked against each report's v2 `policy_hash`, and its SATA key anchors both evidence chains. Length pinned to `PART_POLICY_LEN` (484 B). |
| 16 | `src_mfgr_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Source **sender** manufacturer certificate-chain descriptors (from the `src_evidence` field group). |
| 20 | `src_owner_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Source sender owner certificate-chain descriptors. |
| 24 | `src_part_owner_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Source sender partition-owner certificate-chain descriptors. |
| 28 | `src_report` | `buffer` (single `&ReportDescriptor`, 3 B) | Source sender attestation-report (COSE_Sign1) descriptor; its attested key is `SndrPub`. |
| 32 | `dest_mfgr_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Destination **receiver** manufacturer certificate-chain descriptors (from the `dest_evidence` field group). |
| 36 | `dest_owner_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Destination receiver owner certificate-chain descriptors. |
| 40 | `dest_part_owner_cert_chain` | `buffer` (typed `&[CertDescriptor]`) | Destination receiver partition-owner certificate-chain descriptors. |
| 44 | `dest_report` | `buffer` (single `&ReportDescriptor`, 3 B) | Destination receiver attestation-report (COSE_Sign1) descriptor; its attested key is `DstRcvrPub`. |
| 48 | `src_remote_backup` | `buffer` (fixed 161 B) | Source remote backup to reseal: an HPKE-Auth seal of BKS3 under `DHKemP384Sha384AesGcm256`, `enc(97) ‖ ct(64)` = `POK_REMOTE_BACKUP_LEN` (161 B). |

The two four-entry descriptor blocks are spliced in by the shared
[`Evidence`](../../../fw/core/ddi/tbor/types/src/evidence.rs) field group
(`src_evidence` then `dest_evidence`).  Each descriptor is
`{ index: u8, length: U16 }`: `index` selects a 16-byte NVMe SGL Data
Block descriptor in the **out-of-band** SGL page (SQE `oob_prp`/`oob_len`),
and `length` is the byte count of the referenced payload.  Both evidences'
certificate-chain DER bytes **and** their COSE_Sign1 reports travel out of
band, referenced by these `(offset, length)` descriptors.

### Data section

Carries the 180-byte `masked_sealing_key`, the 484-byte `policy` image,
the packed source / destination cert-chain and report descriptors, and the
161-byte `src_remote_backup` seal.  The referenced evidence payloads (the
two `KeyReport`s and their certificate chains) travel out of band.

## Response

Wire layout: 8-byte header, followed by the TOC entry, then the data
section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `dst_remote_backup` | `buffer` (fixed 161 B) | Resealed remote backup: an HPKE-Auth seal of the same BKS3 to `DstRcvrPub` under `DHKemP384Sha384AesGcm256`, `enc(97) ‖ ct(64)` = `POK_REMOTE_BACKUP_LEN` (161 B). Each reseal re-randomizes the HPKE ephemeral, so the ciphertext differs from `src_remote_backup` and between calls. |

### Data section

Carries the 161-byte `dst_remote_backup` seal.

## Errors

| Error | Cause |
|---|---|
| `TborInvalidFixedLength` | `masked_sealing_key` (180 B), `policy` (484 B), or `src_remote_backup` (161 B) is the wrong length (rejected at decode before the handler runs) |
| `InvalidArg` | Not `Initialized`; missing out-of-band evidence; a report is not v2 (no `policy_hash`); a report's `policy_hash` does not match `SHA-384(policy)`; or evidence chain verification fails |
| `InvalidPermissions` | Not a Crypto-Officer session |
| `UnsupportedKeyScope` | The masked sealing key's scope has no provisioned masking key |
| `UnsupportedKeyType` | The unmasked key is not an `SdSealing` key |
| `AesGcmDecryptTagDoesNotMatch` | `src_remote_backup` fails to HPKE-Auth-open under the recovered receiver key and attested sender key (tampered backup, or mismatched receiver/sender) |
| `SessionNotFound` | `session_id` does not refer to an `Active` slot |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/sd_reseal_remote_backup.rs`
- Source backup: [`SdCreateRemoteBackup`](sd_create_remote_backup.md) produces the `src_remote_backup` this command reseals
- Key provenance: [`SdSealingKeyGen`](sd_sealing_key_gen.md) → [`KeyReport`](key_report.md) mints and attests each party's SD sealing key
