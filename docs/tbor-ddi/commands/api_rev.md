<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# ApiRev (Opcode 0x01)

**Handler:** `fw/core/lib/src/ddi/tbor/api_rev.rs`
**Session:** NoSession

## Description

Returns the inclusive range of TBOR wire-protocol versions the firmware
supports.  Used by the host to pick a compatible version for subsequent
requests on this connection.

## Request

(empty body)

## Response

Wire layout: 8-byte header, followed by the TOC entries, then the
(empty) data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `min_protocol_version` | `uint8` (inline) | Lowest TBOR wire-protocol version the firmware speaks. |
| 12 | `max_protocol_version` | `uint8` (inline) | Highest TBOR wire-protocol version the firmware speaks. |

### Data section

_Empty — both fields are carried inline within their TOC entries._

The shipping firmware currently returns `min = max = 1`.

## Errors

| Error | Cause |
|---|---|
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/api_rev.rs`
