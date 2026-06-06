<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# CloseSession (Opcode 0x12)

**Handler:** `fw/core/lib/src/ddi/tbor/close_session.rs`
**Session:** InSession

## Description

Tears down an Active or Pending session slot, releasing the slot's
session vault blob and any session-scoped keys.  Slot 0 (the Crypto
Officer slot) may be closed and later reopened via a fresh
`OpenSessionInit` with `psk_id = 0`.

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
- Wire schema: `fw/core/ddi/tbor/types/src/close_session.rs`
- Session lifecycle: [`open_session_init.md`](./open_session_init.md),
  [`open_session_finish.md`](./open_session_finish.md)
