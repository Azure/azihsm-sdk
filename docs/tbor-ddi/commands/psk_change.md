<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# PskChange (Opcode 0x06)

**Handler:** `fw/core/lib/src/ddi/tbor/psk_change.rs`
**Session:** InSession

## Description

Replaces the calling session's own partition PSK (Pre-Shared Key) with
a new value supplied encrypted under the session's `param_key`.
"Self-rotate only": the target slot is derived from the session role
(no cross-role rotation surface):

| Active session role | Target PSK slot |
|---|---|
| Crypto Officer (slot 0) | `psk_id = 0` (CO) |
| Crypto User (slot 1..=7) | `psk_id = 1` (CU) |

If the CU PSK is lost or compromised, recovery is **out of scope** for
this command — operators must use an admin-side reset path (factory
reset, partition re-create) rather than a cross-role override from a
CO session.

## Request

Wire layout: 4-byte header, followed by two TOC entries, then the
variable-length data section carrying the AEAD-GCM envelope.

### TOC entries

TOC entries are 4 bytes each (`type ‖ offset` packed); see the [TBOR
spec](../../../fw/core/ddi/tbor/docs/spec.md).

| Offset | Field | Type | Description |
|---|---|---|---|
| 4 | `session_id` | `session_id` (inline) | Session whose `param_key` wraps `psk_envelope`. |
| 8 | `psk_envelope` | `buffer` (fixed 100 B) | AEAD-GCM envelope (see below); points into the data section. Length is pinned to exactly 100 B (`PSK_CHANGE_ENVELOPE_LEN`); a wrong length is rejected at decode. |

### Data section

| Offset | Field | Description |
|---|---|---|
| 12 | `psk_envelope` bytes | Raw AEAD-GCM envelope; length stored in the TOC entry above. |

### `psk_envelope` contents

Built by the host with [`aead_envelope::seal`](
../../../crates/crypto/src/aead_envelope/) under the active session's
`param_key` (32-byte AES-256 key, AEAD-GCM):

* **Plaintext:** exactly **32 bytes** = the new PSK value (`PSK_LEN`).
* **AAD** (wire-embedded, **32 bytes**, authenticated by the AEAD tag):

  | Offset | Size | Field | Description |
  |---|---|---|---|
  | 0  | 13 B | `label` | ASCII `"psk-change-v1"` |
  | 13 | 2 B  | `session_id` | Little-endian; same value as the TOC `session_id` field |
  | 15 | 17 B | `rsv0` | Zero padding so AAD length is a multiple of 32 (the `aead_envelope` granularity invariant) |

  The shared helper [`build_psk_change_aad`](
    ../../../fw/core/ddi/tbor/types/src/psk_change.rs) — re-exported
  from the host wrapper — produces these bytes; the FW handler
  reconstructs the identical buffer via the same helper and rejects
  any contents mismatch with `AeadEnvelopeAuthFailed`.

  No `target_psk_id` is bound in the AAD: the target slot is implicit
  in the session role, so there is no slot-selection byte the AAD
  needs to pin.

* **Envelope wire layout** (exact 100 bytes for a 32-byte PSK):

  ```
  "AEAD"(4) | alg=0x03(1) | rsv=0(1) | aad_len_be=32(2)
          | IV(12) | AAD(32) | psk_ct(32) | TAG(16)
  ```

## Response

(empty body)

## Errors

| Error | Cause |
|---|---|
| `SessionNotFound` | `session_id` does not refer to an Active slot in the calling partition (slot free, destroyed, or still Pending) |
| `TborInvalidFixedLength` | `psk_envelope` is not exactly 100 B (rejected at decode before the handler runs) |
| `InvalidArg` | Decrypted plaintext length ≠ 32; AAD length on the envelope ≠ 32 |
| `AeadEnvelopeAuthFailed` | Envelope AEAD-GCM tag verification failed (wrong `param_key`, tampering, or AAD **contents** do not match the expected layout) |
| `InvalidPermissions` | A `PskChange` has already succeeded on this session (one-rotation-per-session bound) |
| `InternalError` | Session vault blob shorter than expected; indicates internal corruption |

## Replay model

* **Cross-session replay** is structurally impossible: `param_key` is
  HPKE-derived per session, so an envelope captured from session *A*
  cannot decrypt under session *B*'s key (the AEAD tag fails before
  any plaintext is produced).
* **Intra-session replay** is bounded to **one successful change per
  session**: the handler atomically marks the session as "change
  used" on success.  A second `PskChange` on the same session is
  rejected with `InvalidPermissions`.  The flag resets whenever the
  slot is rebound to fresh key material — closing and re-opening the
  session, letting it expire, or a successful renegotiation
  (`session_recreate` / `session_promote`).

## Default PSKs

Partitions ship with well-known default PSKs returned by
[`HsmPartManager::part_psk`](
  ../../../fw/pal/traits/src/part.rs) when no rotated value has been
persisted:

| Slot | Default value (32 bytes, ASCII + `-` padding) |
|---|---|
| `0` (CO) | `AZIHSM-DEFAULT-CO-PSK-v1--------` |
| `1` (CU) | `AZIHSM-DEFAULT-CU-PSK-v1--------` |

Deployments **must** rotate both via `PskChange` on first
provisioning; the defaults are public by design.

Until rotation completes, the TBOR dispatcher refuses to run any
other in-session command on a session authenticated against the
default PSK — only `PskChange` and `SessionClose` are permitted.
See the [Default-PSK gate](../README.md#default-psk-gate) section in
the TBOR DDI README for the full bootstrap sequence.

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- FW schema: `fw/core/ddi/tbor/types/src/psk_change.rs`
- Host wrapper + AAD helper: `ddi/tbor/types/src/psk_change.rs`
- AEAD envelope crate: `fw/core/crypto/aead-envelope/src/lib.rs`
- Session lifecycle: [`session_open_init.md`](./session_open_init.md),
  [`session_open_finish.md`](./session_open_finish.md),
  [`session_close.md`](./session_close.md)
