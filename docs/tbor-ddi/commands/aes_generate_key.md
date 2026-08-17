<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# AesGenerateKey (Opcode 0x15)

**Handler:** `fw/core/lib/src/ddi/tbor/aes_generate_key.rs`
**Session:** InSession

## Description

Generates a fresh random AES key of the caller-selected size (128 / 192 /
256 bits) and returns it as a **masked** blob. The key is **not** stored
on the device: it is masked (AEAD-GCM-256) under the masking key
associated with the requested `scope`, and the caller holds the masked
blob and passes it back to [`AesEncryptDecrypt`](./aes_encrypt_decrypt.md)
to transform data (unmask-on-use). This is the TBOR analogue of MBOR
`AesGenerateKey`, but with no vault `key_id` / `key_tag` — nothing is
persisted, so the command records no rollback on the undo log.

The `key_size` selects the AES key length:

- AES-128 → 16-byte key, 148-byte masked blob.
- AES-192 → 24-byte key, 156-byte masked blob.
- AES-256 → 32-byte key, 164-byte masked blob.

Only the non-bulk key sizes are generated here (mirroring MBOR
`AesGenerateKey`); the XTS / GCM bulk variants are intentionally absent.

Scope → masking key (resolved on-device):

- `Session` → the per-session masking key (works for any Active session,
  including before `PartFinal`).
- `Ephemeral` → the partition `PartitionEphemeralMaskingKey`.
- `Local` → the partition `PartitionLocalMaskingKey`.
- `SecurityDomain` → the security-domain masking key (`SDMK`).

The `Ephemeral` / `Local` / `SecurityDomain` masking keys are provisioned
by `PartFinal` / `CreateSD`, so a non-`Session` scope before the partition
is `Initialized` is rejected with `InvalidArg`, and `SecurityDomain`
before `CreateSD` with `UnsupportedKeyScope`. The masked key's metadata
records the key as an AES cipher key (`encrypt` + `decrypt`, `local`) plus
the requested scope.

Available to **both Crypto-Officer and Crypto-User** sessions.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| 8 | `scope` | `uint8` (inline) | Requested key scope (`KeyScope` discriminant): `1` = Session, `2` = Ephemeral, `3` = Local, `4` = SecurityDomain. |
| 12 | `key_size` | `uint8` (inline) | AES key size (`AesKeySize` discriminant): `1` = AES-128, `2` = AES-192, `3` = AES-256. |

### Data section

_Empty — all fields are carried inline within their TOC entries._

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `masked_key` | `buffer` (148 / 156 / 164 B) | The generated AES key, masked (AEAD-GCM-256) under the scope's masking key: `header(8) ‖ iv(12) ‖ aad(96) ‖ pt(key) ‖ tag(16)`. Not stored on-device. |

### Data section

Carries the masked key (148 / 156 / 164 B for AES-128 / 192 / 256).

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an allocated slot, or the slot is not `Active` |
| `InvalidArg` | A non-`Session` scope was requested before the partition is `Initialized`, or an unknown `key_size` |
| `UnsupportedKeyScope` | The requested scope has no masking key yet (e.g. `SecurityDomain` before `CreateSD`) |
| `DefaultPskMustRotate` | The calling role's PSK is still the compiled-in default (dispatcher, pre-handler) |
| `DdiDecodeFailed` | Malformed request body |

## See also

- [`AesEncryptDecrypt`](./aes_encrypt_decrypt.md) — transform data with the masked key
- [`UnwrapKey`](./unwrap_key.md) — import an existing AES key as a masked blob
- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/aes_generate_key.rs`
