<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# EccSign (Opcode 0x18)

**Handler:** `fw/core/lib/src/ddi/tbor/ecc_sign.rs`
**Session:** InSession

## Description

Produces a raw ECDSA `r ‖ s` signature over a host-supplied
**pre-computed digest** using a caller-held **masked** ECC private key
(from [`EccGenerateKey`](./ecc_generate_key.md) or imported via
[`UnwrapKey`](./unwrap_key.md)).

The device unmasks the key **in place** in the request buffer (recovering
its curve from the blob's key kind), checks the `sign` usage attribute,
signs, and returns the signature.  The recovered plaintext key is
scrubbed from the request buffer on every path.  Firmware does **no**
hashing — the caller supplies the digest.  This is the TBOR analogue of
MBOR `EccSign`, keyed by a masked blob instead of a vault id.

The digest is supplied and consumed in PKA-native **little-endian** byte
order (the natural big-endian digest with all bytes reversed); the device
flips endianness internally if its signing primitive is big-endian native
(e.g. OpenSSL on the emulator).

Available to **both Crypto-Officer and Crypto-User** sessions.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| 8 | `masked_key` | `buffer` (164..=200 B) | The masked ECC private key; unmasked in place.  Its kind recovers the curve. |
| — | `digest` | `buffer` (32 / 48 / 64 B) | The pre-computed message digest in wire little-endian order. Its length must be a supported SHA-2 digest length (32 / 48 / 64 B); the hash algorithm is inferred from that length, so no separate algorithm selector is carried on the wire. |

### Data section

Carries the masked key followed by the digest.

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `signature` | `buffer` (64 / 96 / 136 B) | Raw ECDSA `r ‖ s`, each component little-endian and padded to the curve wire coordinate length. |

### Data section

Carries the wire-format signature.

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an `Active` slot |
| `InvalidArg` | `digest` length is not a supported SHA-2 digest length (32 / 48 / 64 B), or exceeds the curve's ECDSA field width |
| `InvalidKeyType` | The masked blob is not an ECC private key |
| `InvalidPermissions` | The key's `sign` usage attribute is not set |
| `MaskedKeyDecodeFailed` / `AesGcmDecryptTagDoesNotMatch` | The masked key is malformed or fails authentication (wrong scope / tampered) |
| `DefaultPskMustRotate` | The calling role's PSK is still the compiled-in default (dispatcher, pre-handler) |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Generate a signing key: [`ecc_generate_key.md`](./ecc_generate_key.md)
- Import a signing key: [`unwrap_key.md`](./unwrap_key.md)
- Wire schema: `fw/core/ddi/tbor/types/src/ecc_sign.rs`
