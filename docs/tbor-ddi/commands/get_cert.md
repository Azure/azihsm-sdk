<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# GetCertificate (Opcode 0x1F)

**Handler:** `fw/core/lib/src/ddi/tbor/get_cert.rs`
**Session:** NoSession

## Description

Out-of-session command — the TBOR analogue of MBOR `GetCertificate`.
Returns a single DER-encoded X.509 certificate from the caller's
partition certificate chain at the requested `(slot_id, cert_id)`,
without first opening a session.  By convention index `0` is the leaf
and the last index is the root; use
[`GetCertChainInfo`](./get_cert_chain_info.md) to learn the chain
length.

The chain is read for the caller's own bound partition (`io.pid()`);
the request does not carry a partition selector.

## Request

Wire layout: 4-byte header, followed by the TOC entries.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `slot_id` | `uint8` (inline) | Certificate chain slot within the caller's partition. |
| 8 | `cert_id` | `uint8` (inline) | Zero-based certificate index; `0` = leaf, last index = root.  Must satisfy `cert_id < num_certs`. |

## Response

Wire layout: 8-byte header, followed by the TOC entries, then the
variable-length data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `certificate` | `buffer` (offset/len) | The DER-encoded X.509 certificate, up to 2048 B. |

### Data section

Carries the `certificate` buffer (the DER-encoded certificate bytes).

## Errors

| Error | Cause |
|---|---|
| `InvalidArg` | `slot_id` or `cert_id` is out of range |
| `InternalError` | A provisioned certificate exceeds the 2048-byte wire bound |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Companion command: [`GetCertChainInfo`](./get_cert_chain_info.md)
- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/get_cert.rs`
