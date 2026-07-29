<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# HmacGenerateKey (Opcode 0x11)

**Handler:** `fw/core/lib/src/ddi/tbor/hmac_generate_key.rs`
**Session:** InSession

## Description

Generates a fresh random **variable-length** HMAC key of the
caller-selected SHA variant and returns it as a **masked** blob.  The key
is **not** stored on the device: it is masked (AEAD-GCM-256) under the
masking key associated with the requested `scope`, and the caller holds
the masked blob and passes it back to [`Hmac`](./hmac.md) to compute a MAC
(unmask-on-use).  Because nothing is persisted, the command records no
rollback on the undo log.

The `hash_algo` selects the SHA variant (the HMAC PRF and the MAC tag
length), and `key_length` selects the key length.  HMAC keys are stored
as the variable-length `VarLenHmacSha*` kind, so `key_length` must fall in
the variant's `[min, max]` range — matching the reference firmware's
`VarLenHmacSha*` bounds — else the command returns `InvalidKeyLength`:

| `hash_algo` | key length (min–max) | masked blob (`132 + key_length`) |
|---|---|---|
| SHA-256 | 32–64 | 164–196 B |
| SHA-384 | 48–128 | 180–260 B |
| SHA-512 | 64–128 | 196–260 B |

Scope → masking key (resolved on-device):

- `Session` → the per-session masking key (works for any Active session,
  including before `PartFinal`).
- `Ephemeral` → the partition `PartitionEphemeralMaskingKey`.
- `Local` → the partition `PartitionLocalMaskingKey`.
- `SecurityDomain` → the security-domain masking key (`SDMK`).

The `Ephemeral` / `Local` / `SecurityDomain` masking keys are provisioned
by `PartFinal` / `CreateSD`, so a non-`Session` scope before the partition
is `Initialized` is rejected with `InvalidArg`, and `SecurityDomain`
before `CreateSD` with `UnsupportedKeyScope`.  The masked key's metadata
records the key as an HMAC signing key (`sign` + `verify`, `local`) plus
the requested scope.

Unlike the security-domain administrative commands, this command is
available to **both Crypto-Officer and Crypto-User** sessions.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| 8 | `scope` | `uint8` (inline) | Requested key scope (`KeyScope` discriminant): `1` = Session, `2` = Ephemeral, `3` = Local, `4` = SecurityDomain. |
| 12 | `hash_algo` | `uint8` (inline) | HMAC hash variant (`HashAlgo` discriminant): `1` = SHA-256, `2` = SHA-384, `3` = SHA-512. |
| 16 | `key_length` | `uint8` (inline) | Requested key length in bytes; must be in the variant's `[min, max]` range (see table above). |

### Data section

_Empty — all fields are carried inline within their TOC entries._

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `masked_key` | `buffer` (164–260 B) | The generated HMAC key, masked (AEAD-GCM-256) under the scope's masking key: `header(8) ‖ iv(12) ‖ aad(96) ‖ pt(key) ‖ tag(16)`. Not stored on-device. |

### Data section

Carries the masked key (`132 + key_length` B).

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an allocated slot, or the slot is not `Active` |
| `InvalidArg` | A non-`Session` scope was requested before the partition is `Initialized`, or an unknown `hash_algo` |
| `InvalidKeyLength` | `key_length` is outside the variant's `[min, max]` range (incl. `0`) |
| `UnsupportedKeyScope` | The requested scope has no masking key yet (e.g. `SecurityDomain` before `CreateSD`) |
| `DefaultPskMustRotate` | The calling role's PSK is still the compiled-in default (dispatcher, pre-handler) |
| `DdiDecodeFailed` | Malformed request body |

## See also

- [`Hmac`](./hmac.md) — compute a MAC with the masked key
- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/hmac_generate_key.rs`
