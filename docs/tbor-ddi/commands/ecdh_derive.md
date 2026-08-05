<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# EcdhDerive (Opcode 0x19)

**Handler:** `fw/core/lib/src/ddi/tbor/ecdh_derive.rs`
**Session:** InSession

## Description

Derives an ECDH shared secret from a caller-held **masked** local ECC
private key (from [`EccGenerateKey`](./ecc_generate_key.md) or imported
via [`UnwrapKey`](./unwrap_key.md)) and a host-supplied peer public key,
and returns the secret as a **masked** blob under the requested scope's
masking key.

The device unmasks the local key **in place** in the request buffer
(recovering its curve from the blob's key kind), checks the `derive`
usage attribute, derives the secret, re-masks it under the target scope,
and scrubs both the recovered local key and the raw secret on every path.
This is the TBOR analogue of MBOR `EcdhKeyExchange`, but re-masking the
secret instead of vaulting it.

The derived-secret blob records the ECDH-secret key kind, `local` +
`derive` usage attributes, the requested scope, and the platform
`{svn, owner}` identity.

Available to **both Crypto-Officer and Crypto-User** sessions.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| — | `scope` | `u8` (inline) | [`KeyScope`] whose masking key wraps the derived secret. |
| 8 | `masked_key` | `buffer` (164..=200 B) | The masked local ECC private key; unmasked in place.  Its kind recovers the curve. |
| — | `peer_pub_key` | `buffer` (64 / 96 / 136 B) | The peer's wire public key `x_le ‖ y_le` (little-endian, P-521 padded), exactly the curve's wire public-key length. |

### Data section

Carries the masked local key followed by the peer public key.

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `masked_secret` | `buffer` (164 / 180 / 198 B) | The derived ECDH shared secret, masked (AEAD-GCM-256) under the scope's masking key. |

### Data section

Carries the masked shared secret.  The masked length is
`132 + secret_len`, where `secret_len` is the curve's raw coordinate size
(32 / 48 / 66 B for P-256 / P-384 / P-521).

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an `Active` slot |
| `InvalidArg` | `peer_pub_key` length ≠ the curve's wire public-key length |
| `InvalidKeyType` | The masked blob is not an ECC private key |
| `InvalidPermissions` | The key's `derive` usage attribute is not set |
| `UnsupportedKeyScope` | The requested target scope's masking key is not provisioned |
| `MaskedKeyDecodeFailed` / `AesGcmDecryptTagDoesNotMatch` | The masked local key is malformed or fails authentication (wrong scope / tampered) |
| `EccPublicKeyValidationFailed` / `EccPointValidationFailed` | The peer public key is out of range or not on the curve |
| `DefaultPskMustRotate` | The calling role's PSK is still the compiled-in default (dispatcher, pre-handler) |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Generate a local key: [`ecc_generate_key.md`](./ecc_generate_key.md)
- Wire schema: `fw/core/ddi/tbor/types/src/ecdh_derive.rs`
