<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# SessionOpenFinish (Opcode 0x04)

**Handler:** `fw/core/lib/src/ddi/tbor/session_open_finish.rs`
**Session:** NoSession

## Description

Phase 2 of the session-establishment handshake.  The host VM submits
its Phase-2 confirmation MAC for the slot reserved by
[`SessionOpenInit`](./session_open_init.md) together with a
fresh 32-byte `seed` sealed as an AEAD-GCM envelope under the
HPKE-derived `param_key`.  The HSM verifies the MAC, AEAD-opens the
seed envelope, derives the per-session key schedule selected by the
`session_type` chosen in Phase 1, and promotes the slot from
`Pending` to `Active`.

All suite-derived sizes in this command (the `mac_fin` MAC length,
the `seed_envelope` AEAD parameters, the `bmk_session` AEAD key
length) follow the `suite_id` selected during Phase 1; the HSM
recovers `suite_id` from the Pending slot itself so the host cannot
re-negotiate it here.  For the only currently registered suite
(`0x01` — `P384HkdfSha384AesGcm256`), the wire sizes shown below
apply verbatim.

`param_key` is HKDF-derived from the HPKE `exported` value on both
sides — the host computes it locally during Phase 2 to seal the
`seed_envelope`, and the HSM computes the same key from its own
`exported` to open the envelope.

The derived schedule always includes `param_key` (per-parameter
AEAD-GCM encryption via [`aead_envelope`](
../../../fw/core/crypto/aead-envelope/src/lib.rs)) and `masking_key`
(host-visible masked-key blobs).  `Authenticated` sessions
additionally derive a per-direction MAC key pair
(`mac_tx_key`, `mac_rx_key`) used to authenticate subsequent command
and response bodies.  See [Derived keys](#derived-keys) below for
the full HKDF schedule.

## Request

Wire layout: 4-byte header, followed by the TOC entries, then the
data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 4  | `session_id` | `session_id` (inline) | Pending session identifier the handshake reserved in Phase 1. |
| 8  | `mac_fin` | `buffer` (ref) | References the `mac_fin` payload below.  TOC word carries `(data_offset = 16, length = 48)`. |
| 12 | `seed_envelope` | `buffer` (ref) | References the `seed_envelope` payload below.  TOC word carries `(data_offset = 64, length = 68)`. |

### Data section

| Offset | Length | Field | Description |
|---|---|---|---|
| 16 | 48 B | `mac_fin` | Phase-2 confirmation MAC, HMAC-SHA-384 keyed on the HPKE `exported` value.  See [Phase-2 confirmation MAC](#phase-2-confirmation-mac-mac_fin) below. |
| 64 | 68 B | `seed_envelope` | AEAD-GCM envelope of a fresh 32-byte `seed` sealed under `param_key` with no AAD.  See [`seed_envelope` format](#seed_envelope-format) below. |

## Response

Wire layout: 8-byte header, followed by the TOC entries, then the
data section.

### TOC entries

| Offset | Field | Type | Description |
|---|---|---|---|
| 8 | `bmk_session` | `buffer` (ref) | References the `bmk_session` payload below.  TOC word carries `(data_offset = 12, length = N)` where `N` is the actual envelope length (≤ 512). |

### Data section

| Offset | Length | Field | Description |
|---|---|---|---|
| 12 | _N_ B | `bmk_session` | Wrapped session-key blob (≤ 512 B, typically 148 B).  See [`bmk_session` envelope](#bmk_session-envelope) below. |

## `seed_envelope` format

`seed_envelope` is a fixed-size 68-byte [`aead_envelope`](
../../../fw/core/crypto/aead-envelope/src/lib.rs) blob sealed by the
host with the AEAD-GCM `AesGcm256` algorithm under `param_key` with
**empty AAD**:

```
"AEAD"(4) | alg=0x03(1) | rsv=0(1) | aad_len_be=0(2)
        | IV(12)        | seed(32)                 | TAG(16)
```

The HSM AEAD-opens this envelope (the AEAD tag itself authenticates
the IV, the empty AAD, and the ciphertext); any failure destroys the
Pending slot and returns `SessionAuthFailure`.  The recovered 32-byte
`seed` is the input to `BK_SESSION` derivation for the response's
`bmk_session` envelope below.

## `bmk_session` envelope

`bmk_session` is an [`aead_envelope`](
../../../fw/core/crypto/aead-envelope/src/lib.rs) blob (AES-256-GCM)
wrapping the freshly-derived `masking_key` under `BK_SESSION`:

```
BK_SESSION  = SP800-108-KBKDF-HMAC-SHA-384(
    key     = BK_BOOT,           // 80-byte partition boot key
    label   = "SESSION_BK",
    context = seed,              // 32-byte seed from seed_envelope
    L       = 32 bytes,          // AES-256 key
)
bmk_session = aead_envelope::seal(
    alg = AesGcm256,
    key = BK_SESSION,
    iv  = random 12 B,
    aad = svn(8 BE) | bks2_index(2 BE) | "SMK\0"(4) | key_length(2 BE) | rsv(16),
    pt  = masking_key,           // 80 B (CO and CU, all session_types)
)
```

Wire layout (148 B total):

```
"AEAD"(4) | alg=0x03(1) | rsv=0(1) | aad_len_be=32(2)
        | IV(12) | AAD(32) | masking_key_ct(80) | TAG(16)
```

Only the `masking_key` is wrapped — transport keys (`param_key`,
`mac_tx_key`, `mac_rx_key`) are never persisted in `bmk_session`.

TBOR sessions do not provide a resume path; a host that wants to
restore a masking-key blob across resets uses the MBOR
`ReopenSession` command instead.

A subsequent `BK_BOOT` rotation (SVN bump) invalidates all previously
issued `bmk_session` blobs.

## Phase-2 confirmation MAC (`mac_fin`)

```
mac_fin = HMAC-SHA-384(
    key = exported,
    msg = "phase2-confirm" ‖ session_id_be ‖ pk_init ‖ pk_hsm ‖ pk_resp,
)
```

Identical input layout to
[`mac_resp`](./session_open_init.md#phase-1-confirmation-mac-mac_resp);
only the 14-byte domain-separation label differs.

## Derived keys

After MAC verify, the HSM expands `exported` (48 B) into per-session
key material via HKDF-SHA-384-Expand.  The set of keys derived
depends on the `session_type` chosen in
[`SessionOpenInit`](./session_open_init.md):

| Key | HKDF label | Length | Derived for |
|---|---|---|---|
| `param_key`   | `"azihsm-session-param-v1"` | 32 B  | All sessions (AES-256 for `aead_envelope`) |
| `masking_key` | `"azihsm-masking-v1"`       | 80 B  | All sessions |
| `mac_tx_key`  | `"azihsm-session-mac-tx-v1"`| 48 B  | `Authenticated` sessions only (HSM → host) |
| `mac_rx_key`  | `"azihsm-session-mac-rx-v1"`| 48 B  | `Authenticated` sessions only (host → HSM) |

`param_key` is a raw 32-byte AES-256 key.  `masking_key` keeps the
80-byte AES-CBC-256 (32 B) + HMAC-SHA-384 (48 B) layout consumed by
the MBOR masked-key subsystem.  MAC keys are raw 48-byte
HMAC-SHA-384 keys.

The derived keys are committed to the slot's session vault blob in
a length-discriminated layout:

| `session_type` | Blob layout | Size |
|---|---|---|
| `PlainText` (CU)        | `api_rev(8) ‖ param_key(32) ‖ masking_key(80)` | 120 B |
| `Authenticated` (CO)    | `api_rev(8) ‖ param_key(32) ‖ masking_key(80) ‖ mac_tx_key(48) ‖ mac_rx_key(48)` | 216 B |

Per-direction MAC keys (`mac_tx`/`mac_rx` rather than a single
shared key) eliminate any risk of a reflected-message attack and
provide built-in domain separation between the two traffic
directions without needing to encode the direction in the MAC
input.

## Errors

| Error | Cause |
|---|---|
| `InvalidArg` | `mac_fin` not 48 bytes, `seed_envelope` not 68 bytes, or `session_id` out of range |
| `SessionNotPending` | Slot is not in `Pending` state |
| `SessionAuthFailure` | MAC verify failed, or `seed_envelope` AEAD-open failed; the Pending slot is destroyed in either case |
| `PartitionNotProvisioned` | Identity key not present |

A late `SessionOpenFinish` arriving against an evicted-and-reused slot
fails MAC verification because the slot now carries a different
`exported` value.  This is the replay/late-arrival defence; no wire
sequence number is needed.

## See also

- Wire encoding: [TBOR specification](../../../fw/core/ddi/tbor/docs/spec.md)
- Wire schema: `fw/core/ddi/tbor/types/src/session_open_finish.rs`
- AEAD envelope crate: `fw/core/crypto/aead-envelope/src/lib.rs`
- Phase 1: [`session_open_init.md`](./session_open_init.md)
- Cleanup: [`session_close.md`](./session_close.md)
