<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# PartInit (Opcode 0x07)

**Handler:** `fw/core/lib/src/ddi/tbor/part_init.rs`
**Session:** InSession (Crypto Officer only)

## Description

Phase 1 of partition provisioning.  Binds the partition to a
deterministic per-partition keypair (the **PTA** — Partition Trust
Anchor) derived from caller-supplied entropy, a caller-asserted
[`PartPolicy`], and the SHA-384 thumbprint of the partition's
**POTA** (Partition Owner Trust Anchor) certificate.

`PartInit` is **write-once** on a partition: a second invocation on
an already-initialized or in-flight partition is refused (the
write-once partition setters reject the duplicate values).  It
transitions the partition from `Enabled → Initializing`; the
follow-up `FinalizePart` handler (TBD) drives `Initializing →
Initialized` after POTA validates the returned PTACSR / PTAReport.

Only **Crypto Officer** sessions may issue `PartInit`; CU callers
receive `InvalidPermissions`.  The default-PSK gate ([README →
Default-PSK gate](../README.md#default-psk-gate)) applies in the
usual way: the caller's CO PSK must already have been rotated by
[`PskChange`](./psk_change.md).

## Cryptographic pipeline

1. **Decode + validate** the caller's `PartPolicy` blob (167 bytes,
   schema-checked by `policy::from_bytes`).
2. **AEAD-open** `mach_seed_envelope` under the session's
   `param_key`; recover the 32-byte `mach_seed` plaintext.
3. **KDF cascade:**
   * `UMS = derive_ums(UDS, mach_seed, policy, pota_thumb)` — the
     Unique Material Secret (per-partition, NIST SP 800-108 / RFC
     5869 cascade).
   * `(PTA_priv, PTA_pub) = derive_pta_keypair(UMS)` — deterministic
     P-384 keypair from the UMS.
4. **Build PTACSR:** PKCS#10 CertificationRequest for `PTA_pub`,
   subject `CN = "Azure Integrated HSM PTA"` and `serialNumber = `
   hex-encoded **PTAID** (`SHA-384("AZIHSM-PTAID-v1" ‖ sec1_pub)[..16]`,
   32 hex chars).  Signed by `PTA_priv` (`ECDSA-P384`).
5. **Build PTAReport:** COSE_Sign1 key-attestation report signed by
   the per-partition identity key (**PID**, owned by `alloc_part`).
   Claims bind `PTA_pub`, the partition policy, and the POTA
   thumbprint via the `report_data` field:

   ```
   report_data = SHA-384( "AZIHSM-PTAReport-v1"
                        ‖ u16_be(|policy|) ‖ policy
                        ‖ u16_be(|thumb|)  ‖ thumb )
               ‖ zeros[..80]
   ```
6. **Commit:** vault-allocate the UMS (`PartitionUniqueMachineSecret`)
   and the PTA private key (`PartitionTrustAnchor`), then write the
   write-once partition fields `(pta_pub, pta_key_id, ums_key_id,
   policy, pota_thumb, sata_thumb, sapota_thumb)` and mark the partition
   `Initializing`.  All
   commits are atomic — a failure before the final
   `part_mark_initializing` rolls back both vault entries.

## Request

Wire layout: 4-byte header, six TOC entries, then the variable-length
data section.

### TOC entries

TOC entries are 4 bytes each (`type ‖ offset` packed); see the [TBOR
spec](../../../fw/core/ddi/tbor/docs/spec.md).

| Offset | Field | Type | Description |
|---|---|---|---|
| 4  | `session_id` | `session_id` (inline) | CO session whose `param_key` wraps `mach_seed_envelope`; cross-checked against the SQE-carried session id. |
| 8  | `mach_seed_envelope` | `buffer` (fixed 100 B) | AEAD-GCM envelope (see below) carrying the 32-byte `mach_seed`. Length is pinned to exactly 100 B (`MACH_SEED_ENVELOPE_LEN`); a wrong length is rejected at decode. |
| 12 | `part_policy` | `buffer` (fixed 484 B) | Unified `PartPolicy` blob bound into the partition's attested state. Length pinned to `PART_POLICY_LEN` (484 B); a wrong length is rejected at decode. |
| 16 | `pota_thumbprint` | `buffer` (fixed 48 B) | SHA-384 thumbprint of the POTA certificate the partition is being provisioned under. |
| 20 | `sata_thumbprint` | `buffer` (fixed 48 B) | SHA-384 thumbprint of the SATA certificate bound to the security domain. |
| 24 | `sapota_thumbprint` | `buffer` (offset/len) | Optional SHA-384 thumbprint of the SAPOTA certificate. An **empty** field means absent; when present it is exactly 48 B. |

### `mach_seed_envelope` contents

Built by the host with [`aead_envelope::seal`](
../../../crates/crypto/src/aead_envelope/) under the active session's
`param_key` (32-byte AES-256 key, AEAD-GCM):

* **Plaintext:** exactly **32 bytes** = the raw `mach_seed`
  (`MACH_SEED_LEN`).
* **AAD** (wire-embedded, **32 bytes**, authenticated by the AEAD tag):

  | Offset | Size | Field | Description |
  |---|---|---|---|
  | 0  | 17 B | `label` | ASCII `"part-init-seed-v1"` |
  | 17 | 2 B  | `session_id` | Little-endian; same value as the TOC `session_id` field |
  | 19 | 13 B | `rsv0` | Zero padding so AAD length is a multiple of 32 (the `aead_envelope` granularity invariant) |

  The shared helper [`build_part_init_mach_seed_aad`](
    ../../../fw/core/ddi/tbor/types/src/part_init.rs) — re-exported
  from the host wrapper — produces these bytes; the FW handler
  reconstructs the identical buffer via the same helper and rejects
  any contents mismatch with `AeadEnvelopeAuthFailed`.

* **Envelope wire layout** (exact 100 bytes for a 32-byte plaintext):

  ```
  "AEAD"(4) | alg=0x03(1) | rsv=0(1) | aad_len_be=32(2)
          | IV(12) | AAD(32) | mach_seed_ct(32) | TAG(16)
  ```

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8  | `pta_csr` | `varlen` (≤ 512 B) | DER-encoded PKCS#10 CertificationRequest for the PTA public key, signed by `PTA_priv`. |
| 12 | `pta_report` | `varlen` (≤ 1024 B) | COSE_Sign1 PTA key-attestation report signed by the partition identity key (PID). |

### Data section

| Offset | Field | Description |
|---|---|---|
| 16 | `pta_csr` bytes | DER PKCS#10; length stored in the TOC entry above. |
| 16 + `len(pta_csr)` | `pta_report` bytes | COSE_Sign1; length stored in the TOC entry above. |

The host is expected to forward both blobs to the partition owner
for POTA validation; the resulting PTA certificate is then handed
back to the partition in the upcoming `FinalizePart` opcode.

## Errors

| Error | Cause |
|---|---|
| `InvalidPermissions` | Calling session is not Crypto Officer. |
| `SessionNotFound` | `session_id` does not refer to an Active CO slot in the calling partition. |
| `TborInvalidFixedLength` | `mach_seed_envelope` is not exactly 100 B, or `part_policy` is not 484 B (rejected at decode before the handler runs). |
| `InvalidArg` | Decrypted plaintext length ≠ 32; AAD length on the envelope ≠ 32; `part_policy` fails schema validation. |
| `AeadEnvelopeAuthFailed` | Envelope AEAD-GCM tag verification failed (wrong `param_key`, tampering, or AAD **contents** do not match the expected layout / `session_id`). |
| `PartStateInvalid` | Partition is not in `Enabled`; e.g. already `Initializing` or `Initialized` (write-once gate via `part_mark_initializing`). |
| `PtaKeyAlreadySet` / `UmsKeyAlreadySet` | A prior `PartInit` already committed PTA or UMS material; write-once setters reject the duplicate. |
| `InternalError` | KDF / signing / encoding internal failure; should not occur on a healthy device. |

## Determinism

For a fixed `(UDS, mach_seed, policy, pota_thumb)` tuple the entire
pipeline is deterministic: the same call inputs always produce
byte-identical `pta_csr` (modulo the ECDSA signature, which is
deterministic via RFC 6979 in the PAL) and byte-identical
`report_data` claims.  This is exercised by
`part_init_determinism_emu` in the integration suite.

## Replay model

* **Cross-session replay** of `mach_seed_envelope` is structurally
  impossible: `param_key` is HPKE-derived per session, so an
  envelope captured from session *A* cannot decrypt under session
  *B*'s key (the AEAD tag fails before any plaintext is produced).
* **Cross-partition replay** is impossible: vault key creation, the
  policy commit, and `part_mark_initializing` all run against the
  CO session's bound partition; an envelope minted for partition *X*
  cannot be replayed into partition *Y* because the SQE routes to a
  different partition's IO scope.
* **Re-initialization replay** is rejected by the write-once
  partition setters (`PtaKeyAlreadySet` / `UmsKeyAlreadySet`) before
  any state mutation.

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- FW schema: `fw/core/ddi/tbor/types/src/part_init.rs`
- FW handler: `fw/core/lib/src/ddi/tbor/part_init.rs`
- Host wrapper + AAD re-export: `ddi/tbor/types/src/part_init.rs`
- PartPolicy schema: `fw/core/ddi/tbor/types/src/policy.rs`
- AEAD envelope crate: `fw/core/crypto/aead-envelope/src/lib.rs`
- Key-report (PTAReport) crate: `fw/core/crypto/key-report/src/lib.rs`
- X.509 CSR builder (PTACSR): `fw/core/crypto/x509-builder/src/csr_builder.rs`
- Session lifecycle: [`session_open_init.md`](./session_open_init.md),
  [`session_open_finish.md`](./session_open_finish.md),
  [`psk_change.md`](./psk_change.md)
