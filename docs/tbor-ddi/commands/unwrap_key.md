<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# UnwrapKey (Opcode 0x14)

**Handler:** `fw/core/lib/src/ddi/tbor/unwrap_key.rs`
**Session:** InSession

## Description

Implements `CKM_RSA_AES_KEY_WRAP` for the TBOR transport: within an open
session, unwrap a host-supplied wrapped-key blob with the partition's
RSA-2048 **unwrapping** key and return the recovered key as a **masked**
blob under the requested scope's masking key. This is the TBOR analogue
of MBOR `RsaUnwrap`, but it re-masks the recovered key (unmask-on-use)
instead of vaulting it under a key handle. Nothing is persisted on the
device, so the command records no rollback on the undo log.

The host first calls [`GetUnwrappingKey`](./get_unwrapping_key.md) to
obtain the partition's RSA-2048 unwrapping public key, then wraps the
key to import as `RSA-OAEP(KEK) ‖ AES-KWP(key)`: a random KEK is
RSA-OAEP-encrypted to the unwrapping key, and the key material is
AES-KWP-wrapped under that KEK. The device resolves the unwrapping
**private** key internally by the partition's `RSA_UNWRAPPING_KEY_ID`
property (no host key reference), OAEP-decrypts the KEK, AES-KWP-unwraps
the payload, decodes it into vault form, and masks it.

`key_class` selects the decode path and the recovered key's usage
attributes:

- `Aes` → raw 16 / 24 / 32-byte AES key; `encrypt` + `decrypt`.
- `Rsa` → DER RSA private key (non-CRT vault kind); `sign` + `decrypt`.
- `RsaCrt` → DER RSA private key (CRT vault kind); `sign` + `decrypt`.
- `Ecc` → PKCS#8 DER ECC private key; `sign` + `derive`.
- `Hmac` → raw 32 / 48 / 64-byte HMAC key (SHA-256 / 384 / 512);
  `sign` + `verify`.

Imported keys are never `local`. For the asymmetric classes (`Rsa`,
`RsaCrt`, `Ecc`) the recovered key's wire public key is re-derived and
returned in `pub_key`; symmetric classes (`Aes`, `Hmac`) return an empty
`pub_key`.

Scope → masking key (resolved on-device):

- `Session` → the per-session masking key (works for any Active session,
  including before `PartFinal`).
- `Ephemeral` → the partition `PartitionEphemeralMaskingKey`.
- `Local` → the partition `PartitionLocalMaskingKey`.
- `SecurityDomain` → the security-domain masking key (`SDMK`).

The `Ephemeral` / `Local` / `SecurityDomain` masking keys are provisioned
by `PartFinal` / `CreateSD`, so a non-`Session` scope before the partition
is `Initialized` is rejected with `InvalidArg`, and `SecurityDomain`
before `CreateSD` with `UnsupportedKeyScope`.

Available to **both Crypto-Officer and Crypto-User** sessions.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| 8 | `scope` | `uint8` (inline) | Requested key scope (`KeyScope` discriminant): `1` = Session, `2` = Ephemeral, `3` = Local, `4` = SecurityDomain. |
| 12 | `key_class` | `uint8` (inline) | Class of the wrapped key (`KeyClass` discriminant): `0` = Aes, `1` = Rsa, `2` = RsaCrt, `3` = Ecc, `4` = Hmac. |
| 16 | `oaep_hash` | `uint8` (inline) | OAEP hash used to wrap the KEK (`HashAlgo` discriminant): `1` = SHA-256, `2` = SHA-384, `3` = SHA-512. |
| 20 | `wrapped_blob` | `buffer` (≤ 3072 B) | The RSA-AES-wrapped key: `RSA-OAEP(KEK) ‖ AES-KWP(key)`. The leading modulus-sized (256 B for RSA-2048) OAEP ciphertext is wire little-endian. |

### Data section

Carries the wrapped-key blob.

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `key_kind` | `uint8` (inline) | The recovered key's `HsmVaultKeyKind` discriminant. |
| 12 | `masked_key` | `buffer` (≤ 3072 B) | The recovered key, masked (AEAD-GCM-256) under the scope's masking key: `header(8) ‖ iv(12) ‖ aad(96) ‖ pt(key) ‖ tag(16)`. Not stored on-device. |
| 16 | `pub_key` | `buffer` (≤ 520 B) | The recovered key's wire public key for RSA (`n_le ‖ e_le`) / ECC (`x ‖ y`); empty for symmetric (AES / HMAC) keys. |

### Data section

Carries the masked key followed by the public key (empty for symmetric
keys).

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an allocated slot, or the slot is not `Active` |
| `InvalidArg` | A non-`Session` scope was requested before the partition is `Initialized`, or an unknown `oaep_hash` |
| `UnsupportedKeyScope` | The requested scope has no masking key yet (e.g. `SecurityDomain` before `CreateSD`) |
| `UnsupportedCmd` | An unknown `key_class` discriminant |
| `PendingKeyGeneration` | The partition's unwrapping key is still being generated; call `GetUnwrappingKey` and retry |
| `RsaUnwrapInvalidRequest` | The wrapped blob is shorter than the modulus-sized OAEP segment |
| `RsaUnwrapInvalidKek` | The recovered KEK has an invalid length |
| `RsaDecryptFailed` | OAEP-decrypt of the KEK failed (wrong unwrapping key, corrupt ciphertext, or `oaep_hash` mismatch) |
| `DefaultPskMustRotate` | The calling role's PSK is still the compiled-in default (dispatcher, pre-handler) |
| `DdiDecodeFailed` | Malformed request body |

## See also

- [`GetUnwrappingKey`](./get_unwrapping_key.md) — fetch the RSA-2048 unwrapping public key
- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/unwrap_key.rs`
