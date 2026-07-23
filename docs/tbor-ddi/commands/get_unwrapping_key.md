<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# GetUnwrappingKey (Opcode 0x13)

**Handler:** `fw/core/lib/src/ddi/tbor/get_unwrapping_key.rs`
**Session:** InSession

## Description

Returns the partition's RSA-2048 **unwrapping** public key, which the
host uses to RSA-AES key-wrap a payload for a future `UnwrapKey` import.

The unwrapping key is a device-provisioned partition-internal key.  Only
its **public** half is returned: the private half never leaves the device
and `UnwrapKey` resolves it internally by the partition's
`RSA_UNWRAPPING_KEY_ID` property, so no host-supplied key reference is
needed.

RSA key generation is expensive, so each PAL materialises the key behind
the property read: the std (emulator) PAL generates it lazily on first
read, while hardware PALs generate it in the background from partition
init and leave the property unset until ready.  An absent key surfaces as
`PendingKeyGeneration` so the host retries.

Available to **both Crypto-Officer and Crypto-User** sessions.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |

### Data section

_Empty._

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `pub_key` | `buffer` (260 B) | The RSA-2048 unwrapping public key in HSM wire format: `n_le(256) ‖ e_le(4)`. |

### Data section

Carries the 260-byte public key.

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an allocated slot, or the slot is not `Active` |
| `PendingKeyGeneration` | The unwrapping key is still being generated; retry |
| `DefaultPskMustRotate` | The calling role's PSK is still the compiled-in default (dispatcher, pre-handler) |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/get_unwrapping_key.rs`
