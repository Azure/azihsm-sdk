<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# PartInfo (Opcode 0x02)

**Handler:** `fw/core/lib/src/ddi/tbor/part_info.rs`
**Session:** NoSession

## Description

Out-of-session info command.  Combines the device-level fields of the
MBOR `GetDeviceInfo` command with the partition's identity and
lifecycle posture, so a host can learn — in a single round-trip and
without first opening a session — what device it is talking to and the
identity/state of the partition it is bound to.

The module-wide FIPS approval status is carried in the standard
response-header `FIPS_APPROVED` flag, not as a body field.

## Request

(empty body)

## Response

Wire layout: 8-byte header, followed by the TOC entries, then the
variable-length data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8  | `device_kind` | `uint8` (inline) | Device kind: `1` = Virtual, `2` = Physical. Unknown values round-trip as `DeviceKind(x)`. |
| 12 | `part_state` | `uint8` (inline) | Partition lifecycle state: `0` = Unallocated, `1` = Allocated, `2` = Enabled, `3` = Disabled, `4` = Initializing. |
| 16 | `generation` | `uint32` (offset/len) | Monotonic partition generation counter. |
| 20 | `owner_svn` | `uint64` (offset/len) | Owner-seed (BKS2) selector currently in effect. |
| 24 | `mfgr_svn` | `uint64` (offset/len) | Manufacturer-seed (BKS1) selector — the current firmware SVN. |
| 28 | `pid` | `buffer` (offset/len) | Opaque 16-byte partition identity (PID). |
| 32 | `pid_pub_key` | `buffer` (offset/len) | Raw ECC-P384 identity public key (`x ‖ y`, 96 B, each 48-byte coordinate little-endian; SEC1 `0x04` prefix stripped). |

### Data section

Carries the `generation`/`owner_svn`/`mfgr_svn` values and the `pid`
(16 B) and `pid_pub_key` (96 B) buffers.  The `device_kind` and
`part_state` fields are carried inline within their TOC entries.

## Errors

| Error | Cause |
|---|---|
| `DdiDecodeFailed` | Malformed request body |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/part_info.rs`
