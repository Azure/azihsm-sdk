<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# KeyReport (Opcode 0x10)

**Handler:** `fw/core/lib/src/ddi/tbor/key_report.rs`
**Session:** InSession

## Description

Attests a **masked key** (as produced by
[`SdSealingKeyGen`](./sd_sealing_key_gen.md)).  The handler unmasks the
key, derives its public component **on-device**, and returns a
PID-signed COSE_Sign1 key-attestation report over it.  The report is
signed by the partition-identity (PID) key — the same signer as the
`PartInit` PTA report — so a relying party can verify it against the
partition's slot-0 certificate chain.

Report building:

1. **Peek** the masked blob's cleartext metadata (AAD) to read the key
   `scope`, and resolve the scope's masking key (`Ephemeral` → the
   partition `PartitionEphemeralMaskingKey`, `Local` → the partition
   `PartitionLocalMaskingKey`).  Both masking keys are provisioned by
   `PartFinal`, so the partition must be in the `Initialized` lifecycle
   state.  Any other scope is rejected with `UnsupportedKeyScope`.
2. **Unmask** the blob (AEAD-GCM-256), which verifies the authenticity
   tag and recovers the private key plus its validated metadata (key
   kind and attributes).
3. **Derive** the attested public key.  Only ECC-private kinds (including
   the P-384 `SdSealing` key) are attestable: they re-derive the public
   point from the recovered private scalar via `pub = priv · G`.  Every
   other kind — symmetric (no public component to bind), RSA-private
   (public-modulus extraction not yet implemented), and non-attestable /
   internal kinds — is rejected with `UnsupportedKeyType`.
4. **Sign** the COSE_Sign1 report (ES384 / ECDSA-P384) with the PID key
   over the derived key, the caller-supplied `report_data`, the session
   app id, and the partition VM launch id.

Because nothing is persisted, the command records no rollback on the undo
log.  The masked blob's `svn` / `owner_seed_id` are **not** enforced
against the current partition lineage: the report reflects the key
as-masked (the AEAD tag still guarantees integrity / authenticity).

This command is **Crypto-Officer-only**: a Crypto-User session is
rejected with `InvalidPermissions`.

## Request

Wire layout: 4-byte header, followed by the TOC entries, then the data
section carrying the masked key and report data.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | CO session this request is bound to; cross-checked against the SQE-carried session id. |
| 8 | `masked_key` | `buffer` (≤ 512 B) | The masked-key envelope to attest, as produced by `SdSealingKeyGen`: `header(8) ‖ iv(12) ‖ aad(96) ‖ pt(N) ‖ tag(16)`. |
| — | `report_data` | `buffer` (128 B) | Caller-supplied data bound into the report payload (typically a freshness nonce or a challenge digest). |

### Data section

Carries the variable-length `masked_key` followed by the 128-byte
`report_data`.

## Response

Wire layout: 8-byte header, followed by the TOC entry, then the data
section carrying the report.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `report` | `buffer` (≤ 1024 B) | The tagged COSE_Sign1 key-attestation report (CBOR tag 18, opening byte `0xD2`), signed by the PID key. The embedded COSE_Key holds the derived public key (big-endian coordinates for ECC). |

### Data section

Carries the variable-length COSE_Sign1 `report`.

## Errors

| Error | Cause |
|---|---|
| `InvalidPermissions` | The calling session is a Crypto User (this command is Crypto-Officer-only) |
| `SessionNotFound` | `session_id` does not refer to an allocated slot, or the slot is not `Active` |
| `InvalidArg` | The partition is not `Initialized` (run `PartFinal` first), or `report_data` is the wrong length |
| `UnsupportedKeyScope` | The masked key's scope (`Session`, `SecurityDomain`, or other) has no masking key yet |
| `AesGcmDecryptTagDoesNotMatch` | The masked key failed authentication (tampered or wrong masking key) |
| `UnsupportedKeyType` | The attested key kind cannot be attested (symmetric, RSA-private, or a non-attestable / internal kind) |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/key_report.rs`
- Report format: `fw/core/crypto/key-report/`
- Masked-key producer: [SdSealingKeyGen](./sd_sealing_key_gen.md)
