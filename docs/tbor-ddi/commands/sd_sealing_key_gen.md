<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SdSealingKeyGen (Opcode 0x09)

**Handler:** `fw/core/lib/src/ddi/tbor/sd_sealing_key_gen.rs`
**Session:** InSession

## Description

Generates a new security-domain sealing key and returns the **masked**
private key together with the public key.  The sealing key is a **P-384
ECC keypair for ECDH key agreement** (ECIES-style seal / unseal).

The private key is **not** stored on the device.  It is masked
(AEAD-GCM-256) under the masking key associated with the requested
`scope` and the masked blob is returned to the caller, which re-imports
it (unmask-on-use) when the key is later needed.  Because nothing is
persisted, the command records no rollback on the undo log.

The request carries the requested key `scope` (lifecycle / visibility
domain) as its 1-byte `KeyScope` discriminant — a wire mirror of the
firmware `HsmKeyScope`.  Scope → masking key:

- `Ephemeral` → the partition `PartitionEphemeralMaskingKey`.
- `Local` → the partition `PartitionLocalMaskingKey`.

Both masking keys are provisioned by `PartFinal`, so the partition must
be in the `Initialized` lifecycle state.  The `Session` and
`SecurityDomain` scopes (and any other) are rejected with
`UnsupportedKeyScope` until their masking keys exist (session-key
masking / `CreateSD`'s `SDKMK`).  The masked key's metadata records the
sealing key as `derive`-only, `local`, `private`, and never-extractable,
plus the requested scope.

This command is **Crypto-Officer-only**: a Crypto-User session is
rejected with `InvalidPermissions`.

## Request

Wire layout: 4-byte header, followed by the TOC entries, then the
(empty) data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | CO session this request is bound to; cross-checked against the SQE-carried session id. |
| 8 | `scope` | `uint8` (inline) | Requested key scope (`KeyScope` discriminant): `0` = Unspecified, `1` = Session, `2` = Ephemeral, `3` = Local, `4` = SecurityDomain, `5` = Internal. Only `Ephemeral` and `Local` are supported; others return `UnsupportedKeyScope`. |

### Data section

_Empty — both fields are carried inline within their TOC entries._

## Response

Wire layout: 8-byte header, followed by the TOC entries, then the data
section carrying the masked key and public key.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `masked_key` | `buffer` (180 B) | The sealing key's ECC-P384 private half, masked (AEAD-GCM-256) under the scope's masking key: `header(8) ‖ iv(12) ‖ aad(96) ‖ pt(48) ‖ tag(16)`. Not stored on-device. |
| 12 | `pub_key` | `buffer` (96 B) | Raw P-384 public key: `x ‖ y` affine coordinates (48 + 48 bytes, little-endian per coordinate) of the new sealing key. Not a SEC1 point encoding (no `0x04` prefix). |

### Data section

Carries the 180-byte `masked_key` followed by the 96-byte `pub_key`.

## Errors

| Error | Cause |
|---|---|
| `InvalidPermissions` | The calling session is a Crypto User (this command is Crypto-Officer-only) |
| `SessionNotFound` | `session_id` does not refer to an allocated slot, or the slot is not `Active` |
| `InvalidArg` | The partition is not `Initialized` (run `PartFinal` first) |
| `UnsupportedKeyScope` | The requested scope (`Session`, `SecurityDomain`, or other) has no masking key yet |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/sd_sealing_key_gen.rs`
