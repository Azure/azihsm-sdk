<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# PartFinal (Opcode 0x08)

**Handler:** Implemented (`fw/core/lib/src/ddi/tbor/part_final.rs`) —
manticore `FinalizePart`. The PTA certificate chain is walked and
validated; only the SD-local key material of `ConfigPartSD` is **not yet
implemented**.
**Session:** InSession (Crypto Officer)

## Description

Finalizes a partition after [`PartInit`](./part_init.md): derives the
partition-local masking keys and returns the current `local_mk` backup.
The caller re-supplies the unified `PartPolicy`, the PTA cert-chain
descriptor list (referencing the certificates carried **out of band** as
SGL Data Blocks), and an optional prior `local_mk` backup to restore.  It
returns the current `local_mk` backup envelope, which the host persists
and replays as `prev_local_mk_backup` on subsequent launches.

## Handler steps

1. **Gate:** CO-only; partition must be in `Initializing`; reject otherwise.
2. **Integrity:** verify `SHA-384(part_policy)` == the stored
   `policy_hash` (bound at `PartInit`); validate the typed policy.
3. **UPS:** read the partition root (UMS) from the `ups_key_id` slot and
   derive `UPS = KBKDF(UMS, "AZIHSM-PartFinal-UPS-v1")` (cert-chain hash
   deferred → empty context).
4. **PartLocalMK:** derive `PartLocalBMK` (svn/owner-bound); generate a
   fresh 32 B `PartLocalMK` (no prior backup) or restore it by unmasking
   `prev_local_mk_backup` and re-mask under the current SVN.
5. **EphemeralMK:** sample a fresh 32 B random masking key.
6. **Commit:** vault `PartLocalMK` (Local scope) + `EphemeralMK`
   (Ephemeral scope) recording their ids; replace UMS → UPS in the root
   slot (free the old UMS key); transition `Initializing → Initialized`.
7. **Respond:** return the 164 B `local_mk_backup`.

## Request

Wire layout: 4-byte header, followed by the TOC entries, then the
variable-length data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4  | `session_id` | `session_id` (inline) | CO session this request is bound to; cross-checked against the SQE-carried session id. |
| 8  | `part_policy` | `buffer` (offset/len) | Caller-asserted unified `PartPolicy` re-supplied from `PartInit`. Length pinned to 484 B. The handler verifies `SHA-384(part_policy)` against the stored policy hash. |
| 12 | `cert_descriptors` | `buffer` (offset/len) | Packed list of `CertDescriptor` entries `(index: u8, length: u16)`, each 3 B little-endian, referencing the DER certificates of the PTA chain carried **out of band** as SGL Data Blocks (selected by descriptor `index`). 1–2 entries (a non-zero multiple of 3 B, up to 6 B). |
| 16 | `prev_local_mk_backup` | `buffer` (offset/len) | Optional previously-generated `local_mk` backup envelope to restore. An **empty** field means absent; when present it is exactly 164 B. |

### Data section

Carries the `part_policy` (484 B), the packed `cert_descriptors`, and
the optional `prev_local_mk_backup` envelope.  The PTA certificate
bytes themselves are **not** in the TBOR message — each `cert_descriptors`
entry's `index` selects an SGL Data Block carried out of band.

`CertDescriptor` elements are `Unaligned` (a `u8` `index` and a
little-endian `U16` `length`), so the typed slice is borrowed zero-copy
with no alignment padding.

## Response

Wire layout: 8-byte header, followed by the TOC entry, then the data
section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `local_mk_backup` | `buffer` (offset/len) | Current `local_mk` backup envelope (`CurrPartLocalMKBackup`). Always exactly 164 B. |

### Data section

Carries the 164-byte `local_mk_backup` envelope.

## Errors

| Error | Cause |
|---|---|
| `TborInvalidFixedLength` | Decode-time length-bound violation: `part_policy` ≠ 484 B, `cert_descriptors` byte length outside `3..=6` B, or `prev_local_mk_backup` > 164 B |
| `InvalidArg` | Handler-time validation: `cert_descriptors` within range but not a whole number of 3-byte descriptors (e.g. 4 or 5 B), or a present `prev_local_mk_backup` not exactly 164 B |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/part_final.rs`
- Partition setup: [`part_init.md`](./part_init.md)
