<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# GetCertChainInfo (Opcode 0x1E)

**Handler:** `fw/core/lib/src/ddi/tbor/get_cert_chain_info.rs`
**Session:** NoSession

## Description

Out-of-session info command — the TBOR analogue of MBOR
`GetCertChainInfo`.  Reports the number of certificates in the caller's
partition certificate chain at the requested slot and the SHA-256
thumbprint of the leaf certificate, so a host can detect chain rotation
without downloading every certificate — and without first opening a
session.

The chain is read for the caller's own bound partition (`io.pid()`);
the request does not carry a partition selector.

## Request

Wire layout: 4-byte header, followed by the TOC entries.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `slot_id` | `uint8` (inline) | Certificate chain slot within the caller's partition (e.g. `0` = identity chain). |

## Response

Wire layout: 8-byte header, followed by the TOC entries, then the
variable-length data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8  | `num_certs` | `uint8` (inline) | Number of certificates in the chain.  Valid `GetCertificate` indices are `0..num_certs`. |
| 12 | `thumbprint` | `buffer` (offset/len) | SHA-256 thumbprint of the leaf certificate (32 B). |

### Data section

Carries the 32-byte `thumbprint` buffer.  The `num_certs` field is
carried inline within its TOC entry.

## Errors

| Error | Cause |
|---|---|
| `InvalidArg` | `slot_id` is out of range for the partition |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Companion command: [`GetCertificate`](./get_cert.md)
- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/get_cert_chain_info.rs`
