<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# HkdfDerive (Opcode 0x1C)

**Handler:** `fw/core/lib/src/ddi/tbor/hkdf_derive.rs`
**Session:** InSession

## Description

Derives key material (AES or HMAC) from a caller-held **masked** ECDH
shared secret (from [`EcdhDerive`](./ecdh_derive.md)) via HKDF
([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869): Extract-then-Expand),
and returns the derived key as a **masked** blob under the requested
scope's masking key.

The device unmasks the input secret **in place** in the request buffer,
checks that its kind is an ECDH shared secret (`Secret256` / `Secret384` /
`Secret521`) carrying the `derive` usage attribute, runs
HKDF-Extract(`salt`, IKM) then HKDF-Expand(PRK, `info`) into scratch,
re-masks the output key under the target scope, and scrubs the recovered
IKM and the derived scratch on every path.  This is the TBOR analogue of
MBOR `HkdfDerive`, but re-masking the derived key instead of vaulting it.

An **empty** `salt` selects the RFC 5869 default (all-zero) salt; an empty
`info` omits the context — both are cryptographically exact (HMAC pads a
shorter-than-block key with zeros).

The derived-key blob records the output key kind, `local` usage plus
`encrypt`/`decrypt` (AES) or `sign`/`verify` (HMAC), the requested scope,
and the platform `{svn, owner}` identity.

Available to **both Crypto-Officer and Crypto-User** sessions.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| — | `scope` | `u8` (inline) | [`KeyScope`] whose masking key wraps the derived key. |
| — | `hash_algo` | `u8` (inline) | [`HashAlgo`] HKDF hash / HMAC PRF (`1` = SHA-256, `2` = SHA-384, `3` = SHA-512). |
| — | `key_type` | `u8` (inline) | [`KdfKeyType`] output key type (AES-128/192/256 = `10`/`11`/`12`; HMAC-SHA-256/384/512 = `25`/`26`/`27`; variable HMAC-256/384/512 = `30`/`31`/`32`). |
| — | `key_length` | `u8` (inline) | Output length in bytes for the `VarHmac*` types; `0` means absent (required for `VarHmac*`, ignored otherwise). |
| 8 | `masked_secret` | `buffer` (164..=198 B) | The masked ECDH shared secret IKM; unmasked in place. |
| — | `salt` | `buffer` (0..=256 B) | Optional HKDF-Extract salt; empty selects the RFC 5869 default salt. |
| — | `info` | `buffer` (0..=256 B) | Optional HKDF-Expand context/application info; empty means none. |

### Data section

Carries the masked secret, followed by the salt, followed by the info.

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `masked_key` | `buffer` (148..=260 B) | The derived key, masked (AEAD-GCM-256) under the scope's masking key. |

### Data section

Carries the masked derived key.  The masked length is `132 + okm_len`,
where `okm_len` is the derived key length (16 / 24 / 32 for AES-128/192/256;
32 / 48 / 64 for HMAC-SHA-256/384/512; `key_length` for `VarHmac*`).

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an `Active` slot |
| `InvalidArg` | Unknown `hash_algo`, or a non-`Session` scope requested before the partition is `Initialized` |
| `InvalidKeyType` | Unknown / unsupported `key_type`, a `VarHmac*` output with `key_length = 0`, or the input blob is not an ECDH shared secret |
| `InvalidKeyLength` | A `VarHmac*` `key_length` outside the per-variant range (256: 32..=64, 384: 48..=128, 512: 64..=128) |
| `InvalidPermissions` | The input secret's `derive` usage attribute is not set |
| `UnsupportedKeyScope` | The requested target scope's masking key is not provisioned |
| `MaskedKeyDecodeFailed` / `AesGcmDecryptTagDoesNotMatch` | The masked secret is malformed or fails authentication (wrong scope / tampered) |
| `DefaultPskMustRotate` | The calling role's PSK is still the compiled-in default (dispatcher, pre-handler) |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Derive the input secret: [`ecdh_derive.md`](./ecdh_derive.md)
- Wire schema: `fw/core/ddi/tbor/types/src/hkdf_derive.rs`
