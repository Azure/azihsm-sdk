<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SdSealingKeyGen (Opcode 0x09)

**Handler:** _Not yet landed — wire schema only._
**Session:** InSession

## Description

Generates a new security-domain sealing key in the active session's
partition vault and returns its key handle.  The request carries the
requested key `scope` (lifecycle / visibility domain) as its 1-byte
`KeyScope` discriminant — a wire mirror of the firmware `HsmKeyScope`.

## Request

Wire layout: 4-byte header, followed by the TOC entries, then the
(empty) data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | CO/CU session this request is bound to; cross-checked against the SQE-carried session id. |
| 8 | `scope` | `uint8` (inline) | Requested key scope (`KeyScope` discriminant): `0` = Unspecified, `1` = Session, `2` = Ephemeral, `3` = Local, `4` = SecurityDomain, `5` = Internal. Unknown values round-trip as `KeyScope(x)`. |

### Data section

_Empty — both fields are carried inline within their TOC entries._

## Response

Wire layout: 8-byte header, followed by the TOC entry, then the
(empty) data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `key_handle` | `key_id` (inline) | Vault id (`HsmKeyId`) of the newly generated sealing key, carried as a `KeyId` (TOC entry type 1). |

### Data section

_Empty — `key_handle` is carried inline within its TOC entry._

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an allocated slot |
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/sd_sealing_key_gen.rs`
