<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# EccGenerateKey (Opcode 0x17)

**Handler:** `fw/core/lib/src/ddi/tbor/ecc_generate_key.rs`
**Session:** InSession

## Description

Generates a fresh ECC keypair on the requested NIST curve (P-256 / P-384
/ P-521) and returns the private key as a **masked** blob under the
requested scope's masking key, plus the wire public key.

The private key is **not** persisted on-device: the caller holds the
masked blob and passes it back to [`EccSign`](./ecc_sign.md) /
[`EcdhDerive`](./ecdh_derive.md) (unmask-on-use).  This is the TBOR
analogue of MBOR `EccGenerateKeyPair`, but without a vault `key_id`.

The masked blob records the key kind (which recovers the curve on
unmask), the `sign` + `derive` usage attributes, the requested scope, and
the platform `{svn, owner}` identity (bound by the AEAD tag for
anti-rollback on re-import).

Available to **both Crypto-Officer and Crypto-User** sessions.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| — | `scope` | `u8` (inline) | [`KeyScope`] whose masking key wraps the private key. |
| — | `curve` | `u8` (inline) | NIST curve: `1` = P-256, `2` = P-384, `3` = P-521. |

### Data section

_Empty._

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `masked_key` | `buffer` (164 / 180 / 200 B) | The private key, masked (AEAD-GCM-256) under the scope's masking key. |
| — | `pub_key` | `buffer` (64 / 96 / 136 B) | The wire public key `x_le ‖ y_le` (little-endian, P-521 padded). |

### Data section

Carries the masked private key followed by the wire public key.  The
masked-key length is `132 + wire_priv_len` (P-521 uses a 68-byte padded
scalar).

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an `Active` slot |
| `InvalidArg` | Unknown curve |
| `UnsupportedKeyScope` | The requested scope's masking key is not provisioned |
| `DefaultPskMustRotate` | The calling role's PSK is still the compiled-in default (dispatcher, pre-handler) |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Sign with the generated key: [`ecc_sign.md`](./ecc_sign.md)
- Derive with the generated key: [`ecdh_derive.md`](./ecdh_derive.md)
- Wire schema: `fw/core/ddi/tbor/types/src/ecc_generate_key.rs`
