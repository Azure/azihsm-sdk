<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Hash (Opcode 0x1B)

**Handler:** `fw/core/lib/src/ddi/tbor/hash.rs`
**Session:** InSession

## Description

Computes a cryptographic hash (SHA-256 / 384 / 512) of a host-supplied
message and returns the digest.  A pure hashing utility — it carries no
key, no scope, and touches no partition state.  This is the TBOR analogue
of MBOR `ShaDigest`.

The handler uses the reserve-then-fill pattern: the response frame is
encoded with the digest slot reserved, then the PAL hashes straight into
it — no intermediate buffer, no copy.  The digest is emitted in natural
(big-endian) byte order.

Available to **both Crypto-Officer and Crypto-User** sessions.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| — | `algo` | `u8` (inline) | Digest algorithm ([`HashAlgo`]): `1` = SHA-256, `2` = SHA-384, `3` = SHA-512. |
| — | `msg` | `buffer` (≤ 2048 B) | The message to hash. |

### Data section

Carries the message bytes.

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `digest` | `buffer` (32 / 48 / 64 B) | The natural (big-endian) digest, exactly the algorithm's length. |

### Data section

Carries the digest.

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an `Active` slot |
| `InvalidArg` | Unknown `algo` |
| `DefaultPskMustRotate` | The calling role's PSK is still the compiled-in default (dispatcher, pre-handler) |
| `DdiDecodeFailed` | Malformed request body (e.g. `msg` exceeds 2048 B) |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/hash.rs`
