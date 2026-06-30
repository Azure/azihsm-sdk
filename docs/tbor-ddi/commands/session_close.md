<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SessionClose (Opcode 0x05)

**Handler:** `fw/core/lib/src/ddi/tbor/session_close.rs`
**Session:** InSession

## Description

Tears down an Active or Pending session slot, releasing the slot's
session vault blob and any session-scoped keys.  Slot 0 (the Crypto
Officer slot) may be closed and later reopened via a fresh
`SessionOpenInit` with `psk_id = 0`.

## Request

Wire layout: 4-byte header, followed by the TOC entry, then the
(empty) data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Slot to destroy. |

### Data section

_Empty — `session_id` is carried inline within its TOC entry._

## Response

(empty body)

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an allocated slot |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/session_close.rs`
- Session lifecycle: [`session_open_init.md`](./session_open_init.md),
  [`session_open_finish.md`](./session_open_finish.md)
