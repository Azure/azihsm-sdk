// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire-format constants and the `KeyFlags` bitfield for COSE_Sign1
//! key-attestation reports.
//!
//! The wire format matches `~/mcr-hsm` and the AZIHSM simulator
//! (`ddi/mbor/sim/src/report.rs`). Encoded lengths are computed at
//! runtime by `minicbor::len` on the [`codec`](crate::codec) structs, so
//! this module holds only the fixed wire facts — not any derived
//! byte-counting arithmetic.

use bitfield_struct::bitfield;

// ─── COSE_Sign1 envelope ────────────────────────────────────────────────────

/// COSE_Sign1 CBOR tag byte (tag 18): major type 6 (`0b110`) | 18.
pub const COSE_SIGN1_TAG: u8 = 0xD2;

/// Size of the COSE_Sign1 tag prefix.
pub const COSE_SIGN1_TAG_SIZE: usize = 1;

/// Encoded protected header `{ 1: -35 (ES384), 3: "application/cbor" }`,
/// emitted as a 22-byte bstr in both the COSE_Sign1 object and the
/// COSE `Sig_structure`.
pub const PROTECTED_HEADER: [u8; 22] = [
    0xa2, 0x01, 0x38, 0x22, 0x03, 0x70, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x2f, 0x63, 0x62, 0x6f, 0x72,
];

// ─── Payload fields ─────────────────────────────────────────────────────────

/// Report format version.
pub const REPORT_VERSION: u16 = 1;

/// Length of the app-UUID field (RFC 4122 binary form).
pub const APP_UUID_LEN: usize = 16;

/// Length of the report-data field.
pub const REPORT_DATA_LEN: usize = 128;

/// Length of the VM launch-ID field.
pub const VM_LAUNCH_ID_LEN: usize = 16;

/// Fixed size of the `public_key` bstr that wraps the inner COSE_Key.
///
/// Sized for a 4096-bit RSA public key (512-byte modulus + 4-byte
/// exponent + 9 CBOR framing bytes = 525). An ECC P-384 COSE_Key
/// occupies ~107 bytes; the remainder is zero-padded and the real
/// length is carried in the `public_key_size` field.
pub const PUBLIC_KEY_MAX_SIZE: usize = 525;

/// Maximum RSA modulus length (4096-bit) carried in an attested key's
/// COSE_Key.
pub const RSA_MODULUS_MAX_LEN: usize = 512;

/// Maximum RSA public-exponent length carried in an attested key's
/// COSE_Key.
pub const RSA_EXPONENT_MAX_LEN: usize = 4;

/// CBOR framing overhead of a maximal RSA COSE_Key map — the map
/// header, the `kty` pair, and the two bstr length headers for `n`
/// (3 bytes at 512) and `e` (1 byte at 4).
pub const RSA_COSE_KEY_FRAMING: usize = 9;

// The fixed `public_key` field must exactly fit a maximal RSA COSE_Key
// (keep the modulus/exponent bounds and the 525-byte field in sync).
const _: () = assert!(
    RSA_MODULUS_MAX_LEN + RSA_EXPONENT_MAX_LEN + RSA_COSE_KEY_FRAMING == PUBLIC_KEY_MAX_SIZE
);

/// Upper bound on the encoded size of a key-attestation report.
///
/// The report is built entirely from fixed-size fields (the 525-byte
/// `public_key`, 128-byte `report_data`, 96-byte signature, etc.), so
/// its length is effectively constant; this bound additionally allows
/// every CBOR integer field (`version`, `public_key_size`, `flags`) to
/// encode at its maximum width. The `report_fits_max_len` test pins it
/// against the byte-identical simulator encoder, and consumers (e.g.
/// the PartInit handler) `const`-assert their response caps against it.
pub const KEY_REPORT_MAX_LEN: usize = 896;

// ─── Signing (ES384 / ECDSA-P384) ──────────────────────────────────────────

/// ECDSA-P384 raw signature length (`r || s`, 48 + 48).
pub const SIGNATURE_LEN: usize = 96;

/// P-384 attestation private-key (raw scalar) length.
pub const PRIV_KEY_LEN: usize = 48;

/// SHA-384 digest length.
pub const SHA384_LEN: usize = 48;

// ─── KeyFlags ───────────────────────────────────────────────────────────────

/// Capability / attribute flags packed into the report's `flags: u32`
/// field. Wire layout matches `~/mcr-hsm` and the AZIHSM simulator.
#[bitfield(u32)]
pub struct KeyFlags {
    /// Whether the key was imported (vs generated on-device).
    pub is_imported: bool,
    /// Whether the key is available for the current session only.
    pub is_session_key: bool,
    /// Whether the key was generated inside the device.
    pub is_generated: bool,
    /// Whether the key can encrypt.
    pub can_encrypt: bool,
    /// Whether the key can decrypt.
    pub can_decrypt: bool,
    /// Whether the key can sign.
    pub can_sign: bool,
    /// Whether the key can verify.
    pub can_verify: bool,
    /// Whether the key can wrap other keys.
    pub can_wrap: bool,
    /// Whether the key can unwrap other keys.
    pub can_unwrap: bool,
    /// Whether the key can derive other keys.
    pub can_derive: bool,
    #[bits(22)]
    _reserved: u32,
}
