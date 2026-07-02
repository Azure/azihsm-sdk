<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SessionOpenInit (Opcode 0x03)

**Handler:** `fw/core/lib/src/ddi/tbor/session_open_init.rs`
**Session:** NoSession

## Description

Phase 1 of the session-establishment handshake.  The host VM supplies
its per-handshake ephemeral public key, a PSK identifier asserting
its role (`0` = Crypto Officer, `1` = Crypto User), the
**`session_type`** it wants to establish (`0` = PlainText,
`1` = Authenticated), and the **`suite_id`** selecting the
cryptographic suite (today only `0x01` —
`P384HkdfSha384AesGcm256` — is implemented).  The HSM runs HPKE
`mode_auth_psk` `send_export` against the partition identity key,
reserves a `Pending` session slot, and returns the HSM's HPKE
response ephemeral together with a Phase-1 confirmation MAC.

**Role ↔ session-type pairing.**  The two are pinned per role; any
other pairing is rejected with `InvalidSessionType`:

| `psk_id` (role) | Required `session_type` |
|---|---|
| `0` (Crypto Officer) | `1` (Authenticated) |
| `1` (Crypto User)    | `0` (PlainText) |

A `PlainText` session derives only `param_key` (per-parameter
AEAD-GCM encryption under [`aead_envelope`](
../../../fw/core/crypto/aead-envelope/src/lib.rs)) and `masking_key`.
An `Authenticated` session also derives `mac_tx_key` / `mac_rx_key`
so subsequent command and response bodies carry an outer per-message
HMAC envelope (see [`session_open_finish.md`](./session_open_finish.md)
for the full key schedule).

The HPKE suite is `DHKEM(P-384, HKDF-SHA-384) + AES-256-GCM`, with
`info = "azihsm-session-v2" ‖ psk_id ‖ session_type ‖ suite_id` and
`exporter_context = "session-exporter"`.  Mixing `psk_id`,
`session_type` and `suite_id` into the HPKE `info` field domain-
separates each role/type/suite combination and makes any attempt to
downgrade `session_type` or `suite_id` produce a different `exported`
on the HSM side — the Phase-1 confirm MAC then fails to verify on
the host.

### Suite registry

The `suite_id` byte selects every other cryptographic primitive used
by the handshake (KEM, KDF, AEAD, MAC).  It is also persisted in the
HSM's Pending slot so `SessionOpenFinish` can recover the negotiated
suite without trusting any client-side state.

| `suite_id` | Suite | KEM | KDF | AEAD | MAC |
|---|---|---|---|---|---|
| `0x01` | `P384HkdfSha384AesGcm256` | HPKE DHKEM(P-384) | HKDF-SHA-384 | AES-256-GCM | HMAC-SHA-384 (48 B) |

`0x01` is the only currently registered suite; any other value is
rejected with `UnsupportedSessionSuite`.  The `suite_id` byte exists
so future suites can be added without a wire-format break — when one
is added it will receive its own row above, and its `pk_init` /
`pk_resp` / `mac_resp` lengths may differ from the values shown for
`0x01`.

Resume is **not** a TBOR concern: a host that wants to reuse a prior
session's masking-key blob does so via the MBOR `ReopenSession`
command.  Every `SessionOpenInit` here is therefore a fresh open.

## Request

Wire layout: 4-byte header, followed by the TOC entries, then the
data section.  Buffer payloads pack contiguously in TOC order.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4  | `psk_id` | `uint8` (inline) | PSK identifier asserting the caller role.  `0` = Crypto Officer, `1` = Crypto User.  Any other value → `InvalidPskId`. |
| 8  | `session_type` | `uint8` (inline) | Channel-level integrity profile.  `0` = PlainText, `1` = Authenticated.  Any other value → `InvalidSessionType`.  Pairing with `psk_id` is enforced (see table above). |
| 12 | `suite_id` | `uint8` (inline) | Cryptographic suite identifier (see [Suite registry](#suite-registry)).  Today only `0x01` is accepted; any other value → `UnsupportedSessionSuite`. |
| 16 | `pk_init` | `buffer` (ref) | References the `pk_init` payload below.  TOC word carries `(data_offset = 20, length = Npk)`.  For `suite_id = 0x01` `Npk = 97`. |

### Data section

| Offset | Length | Field | Description |
|---|---|---|---|
| 20  | `Npk` (97 B for `0x01`) | `pk_init` | VM's per-handshake ephemeral key.  For `suite_id = 0x01` this is a P-384 SEC1 uncompressed public key (`0x04 ‖ x(48) ‖ y(48)`).  Used as the HPKE recipient key in `auth_psk` send/receive export. |

## Response

Wire layout: 8-byte header, followed by the TOC entries, then the
data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8  | `session_id` | `session_id` (inline) | Reserved Pending slot index (`0` for CO, `1..=7` for CU). |
| 12 | `pk_resp` | `buffer` (ref) | References the `pk_resp` payload below.  TOC word carries `(data_offset = 20, length = Npk)`. |
| 16 | `mac_resp` | `buffer` (ref) | References the `mac_resp` payload below.  TOC word carries `(data_offset = 20 + Npk, length = Nh)`. |

### Data section

| Offset | Length | Field | Description |
|---|---|---|---|
| 20 | `Npk` (97 B for `0x01`) | `pk_resp` | HSM's HPKE response ephemeral public key.  For `suite_id = 0x01` this is a P-384 SEC1 uncompressed point (distinct from the long-term `pk_hsm` — this is the per-handshake `enc` value from `auth_encap`). |
| 20 + `Npk` | `Nh` (48 B for `0x01`) | `mac_resp` | Phase-1 confirmation MAC, HMAC over the suite's KDF hash keyed on the HPKE `exported` value.  See [Phase-1 confirmation MAC](#phase-1-confirmation-mac-mac_resp) below. |

## Phase-1 confirmation MAC (`mac_resp`)

```
mac_resp = HMAC-SHA-384(
    key = exported,
    msg = "phase1-confirm" ‖ session_id_be ‖ pk_init ‖ pk_hsm ‖ pk_resp,
)
```

- `exported` is the 48-byte HPKE export produced by `send_export` /
  `receive_export`.
- `session_id_be` is the 2-byte big-endian wire encoding of `session_id`.
- `pk_hsm` is the partition identity public key (SEC1 uncompressed,
  97 bytes).

A successful verify by the VM proves the responder holds `sk_hsm` and
the correct PSK.

## Errors

| Error | Cause |
|---|---|
| `InvalidPskId` | `psk_id` is neither `0` nor `1` |
| `InvalidSessionType` | `session_type` is not `0`/`1`, or pairing with `psk_id` is not the required one (CO must be `Authenticated`, CU must be `PlainText`) |
| `UnsupportedSessionSuite` | `suite_id` is not a value implemented by this firmware build (see [Suite registry](#suite-registry)) |
| `InvalidArg` | `pk_init` malformed (wrong length for the negotiated suite, not SEC1 uncompressed) |
| `EccPointValidationFailed` | `pk_init` off-curve or identity |
| `PartitionNotEnabled` | Partition is not in `Enabled` state |
| `PartitionNotProvisioned` | Identity key not present |
| `VaultSessionLimitReached` | No eligible Pending slot available for the asserted role |

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/session_open_init.rs`
- Phase 2: [`session_open_finish.md`](./session_open_finish.md)
