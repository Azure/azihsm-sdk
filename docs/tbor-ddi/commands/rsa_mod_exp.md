<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# RsaModExp (Opcode 0x1A)

**Handler:** `fw/core/lib/src/ddi/tbor/rsa_mod_exp.rs`
**Session:** InSession

## Description

Performs the RSA private-key primitive `x = y^d mod n` using a
caller-held **masked** RSA private key (imported via
[`UnwrapKey`](./unwrap_key.md) with the RSA / RSA-CRT key class).

The device unmasks the key **in place** in the request buffer (recovering
its modulus size and CRT form from the blob's key kind), checks the usage
attribute the requested operation needs, computes the modular
exponentiation, and returns the result.  The recovered plaintext key is
scrubbed from the request buffer on every path.  This is the raw primitive
underlying RSA decrypt / sign — the host applies and removes any padding.
This is the TBOR analogue of MBOR `RsaModExp`, keyed by a masked blob
instead of a vault id.

There is no TBOR RSA key generation; RSA keys enter the device only
through `UnwrapKey`.

Both the input `y` and the output `x` are in PKA-native **little-endian**
byte order; the device flips endianness internally if its primitive is
big-endian native (e.g. OpenSSL on the emulator).

Available to **both Crypto-Officer and Crypto-User** sessions.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| 8 | `masked_key` | `buffer` (164..=3072 B) | The masked RSA private key; unmasked in place.  Its kind recovers the modulus size and CRT form. |
| — | `op_type` | `u8` (inline) | The [`RsaOp`] selecting the required usage attribute: `1` = Decrypt (needs `decrypt`), `2` = Sign (needs `sign`). |
| — | `y` | `buffer` (256 / 384 / 512 B) | The input integer `y` in wire little-endian order, exactly the key's modulus length. |

### Data section

Carries the masked key followed by the input integer.

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `x` | `buffer` (256 / 384 / 512 B) | The result `x = y^d mod n` in wire little-endian order, exactly the key's modulus length. |

### Data section

Carries the result integer.

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an `Active` slot |
| `InvalidArg` | Unknown `op_type`, or `y` length ≠ the key's modulus length |
| `InvalidKeyType` | The masked blob is not an RSA private key |
| `InvalidPermissions` | The key lacks the usage the operation needs (`decrypt` for Decrypt, `sign` for Sign) |
| `MaskedKeyDecodeFailed` / `AesGcmDecryptTagDoesNotMatch` | The masked key is malformed or fails authentication (wrong scope / tampered) |
| `DefaultPskMustRotate` | The calling role's PSK is still the compiled-in default (dispatcher, pre-handler) |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Import an RSA key: [`unwrap_key.md`](./unwrap_key.md)
- Wire schema: `fw/core/ddi/tbor/types/src/rsa_mod_exp.rs`
