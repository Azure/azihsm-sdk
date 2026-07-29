<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Hmac (Opcode 0x12)

**Handler:** `fw/core/lib/src/ddi/tbor/hmac.rs`
**Session:** InSession

## Description

Computes an HMAC tag over a host-supplied message using a caller-held
**masked** HMAC key (the `masked_key` returned by
[`HmacGenerateKey`](./hmac_generate_key.md) or imported via unwrap).

The masked key's scope is read from its cleartext, tag-bound metadata to
select the masking key; the key is unmasked **in place** in the inbound
request buffer (verifying the AEAD tag), the MAC is computed, and the tag
is returned.  Nothing is persisted, and the recovered key is wiped in
place from the request buffer once the MAC is computed.

The key's kind selects the MAC algorithm and tag length (SHA-256 / 384 /
512 → 32 / 48 / 64 bytes).  The key must carry the `sign` (`C_Sign`)
permission.

Unlike the security-domain administrative commands, this command is
available to **both Crypto-Officer and Crypto-User** sessions.

## Request

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session this request is bound to; cross-checked against the SQE-carried session id. |
| 8 | `masked_key` | `buffer` (164..=260 B) | The masked HMAC key (from `HmacGenerateKey` / unwrap), an AEAD-GCM-256 envelope. Its scope selects the masking key; its kind selects the SHA variant. |
| 12 | `msg` | `buffer` (≤ 1024 B) | The message to MAC. |

### Data section

Carries the masked key followed by the message.

## Response

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `tag` | `buffer` (32 / 48 / 64 B) | The HMAC tag over `msg` (SHA-256 / 384 / 512). |

### Data section

Carries the tag.

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an allocated slot, or the slot is not `Active` |
| `InvalidKeyType` | The masked key is not an HMAC key |
| `InvalidPermissions` | The masked key lacks the `sign` (`C_Sign`) permission |
| `AesGcmDecryptTagDoesNotMatch` | The masked key failed AEAD authentication (tampered / wrong scope / wrong masking key) |
| `UnsupportedKeyScope` | The masked key's scope has no masking key on this partition |
| `DefaultPskMustRotate` | The calling role's PSK is still the compiled-in default (dispatcher, pre-handler) |
| `DdiDecodeFailed` | Malformed request body |

## See also

- [`HmacGenerateKey`](./hmac_generate_key.md) — generate the masked HMAC key
- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/hmac.rs`
