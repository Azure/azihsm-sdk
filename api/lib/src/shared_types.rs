// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Common types used across the HSM library.
//!
//! This module provides core type definitions including key classes, key kinds,
//! and elliptic curve identifiers that are shared between the library and native layers.

use open_enum::open_enum;
use zerocopy::*;

/// A single DER-encoded certificate in a certificate chain.
///
/// Borrowed view over one cert's DER bytes, used by the
/// partition-provisioning API (e.g. [`HsmSession::part_final_ex`]) to accept
/// a PTA chain as `&[HsmCert]`. It is a Rust borrow, **not** an
/// ABI-stable `#[repr(C)]` type; a future native `part_final` FFI would
/// build it from a C array of `{ data, len }` buffers (borrowing, not
/// copying). The wire-level `(index, length)` OOB descriptors stay
/// internal to the SDK.
///
/// [`HsmSession::part_final_ex`]: crate::HsmSession::part_final_ex
#[derive(Debug, Clone, Copy)]
pub struct HsmCert<'a> {
    /// DER-encoded bytes of the certificate.
    pub cert: &'a [u8],
}

/// Result of a security-domain partition-finalization (`part_final_ex`)
/// command: the artifacts the device returns after finalizing a
/// partition's security domain.
///
/// API-layer type with owned bytes. The DDI/wire response type
/// (`TborPartFinalResp`) is converted into it inside the DDI layer, so the
/// wire type never surfaces to public callers.
#[derive(Debug, Clone, Default)]
pub struct HsmPartFinalExResult {
    /// Current `local_mk` backup envelope the firmware produced.
    pub local_mk_backup: Vec<u8>,
}

/// Cryptographic key class.
///
/// Defines the fundamental category of a cryptographic key.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
pub enum HsmKeyClass {
    /// Symmetric secret key (e.g., AES, HMAC).
    Secret = 1,

    /// Public key from an asymmetric key pair.
    Public = 2,

    /// Private key from an asymmetric key pair.
    Private = 3,
}

/// Cryptographic key algorithm type.
///
/// Specifies the algorithm family for a cryptographic key.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
pub enum HsmKeyKind {
    /// RSA asymmetric key kind.
    Rsa = 1,

    /// Elliptic Curve (EC) asymmetric key kind.
    Ecc = 2,

    /// Advanced Encryption Standard (AES) symmetric key kind.
    Aes = 3,

    /// AES XTS symmetric key kind.
    AesXts = 4,

    /// Shared secret key kind.
    SharedSecret = 5,

    /// HMAC SHA 1 is not supported.
    // HmacSha1 = 6,

    /// HMAC SHA 256
    HmacSha256 = 7,

    /// HMAC SHA 384
    HmacSha384 = 8,

    /// HMAC SHA 512
    HmacSha512 = 9,

    /// AES GCM symmetric key kind.
    AesGcm = 10,

    /// HSM Sealing key kind (used for sealing/unsealing operations).
    Sealing = 11,
}

/// Elliptic Curve Cryptography (ECC) curve identifier.
///
/// Specifies the elliptic curve used for ECC keys, as defined by NIST.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
pub enum HsmEccCurve {
    /// NIST P-256 curve (secp256r1), 256-bit security.
    P256 = 1,
    /// NIST P-384 curve (secp384r1), 384-bit security.
    P384 = 2,
    /// NIST P-521 curve (secp521r1), 521-bit security.
    P521 = 3,
}

impl HsmEccCurve {
    /// Returns the key size in bits for the ECC curve.
    pub fn key_size_bits(&self) -> usize {
        match self {
            HsmEccCurve::P256 => 256,
            HsmEccCurve::P384 => 384,
            HsmEccCurve::P521 => 521,
        }
    }

    /// Returns the signature size in bytes for the ECC curve.
    pub fn signature_size(&self) -> usize {
        self.component_size() * 2
    }

    /// Returns the component size in bytes for the ECC curve.
    pub fn component_size(&self) -> usize {
        match self {
            HsmEccCurve::P256 => 32,
            HsmEccCurve::P384 => 48,
            HsmEccCurve::P521 => 66,
        }
    }
}

/// HSM partition type.
///
/// Indicates whether the partition is a virtual (simulated) or physical (hardware) device.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
pub enum HsmPartType {
    /// Virtual/simulated partition.
    Virtual = 1,

    /// Physical hardware partition.
    Physical = 2,
}

/// Owner backup key source.
///
/// Specifies the source of the owner backup key (OBK) during partition initialization.
#[repr(u32)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
pub enum HsmOwnerBackupKeySource {
    /// Caller provided backup key.
    Caller = 1,

    /// TPM-sealed backup key (retrieved from device and unsealed).
    Tpm = 2,
}

/// HSM partition owner trust anchor (aka POTA) endorsement source.
#[repr(u32)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
pub enum HsmPotaEndorsementSource {
    /// Caller provided endorsement.
    Caller = 1,

    /// TPM-generated endorsement.
    Tpm = 2,
}

/// Channel-level integrity profile for a security-domain (TBOR) session,
/// selected by the caller when opening a session via `open_session_ex`.
///
/// API-layer mirror of `azihsm_ddi_tbor_types::SessionType`; kept as a
/// separate `#[open_enum]` so the public API surface does not leak the
/// DDI-layer wire type.
#[repr(u32)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
pub enum HsmSessionExType {
    /// Channel transports bodies without per-message MAC.
    PlainText = 0,

    /// Channel transports bodies wrapped in an outer per-message HMAC
    /// envelope.
    Authenticated = 1,
}

/// Length, in bytes, of a partition PSK (Pre-Shared Key). This module is
/// shared with the native crate (which does not depend on the wire-types
/// crate), so the value is a literal here and pinned to the wire-schema
/// `PSK_LEN` by a static assert in the DDI layer.
pub const PSK_LEN: usize = 32;

/// Partition PSK slot for a security-domain (TBOR) session, selecting
/// which PSK the handshake authenticates with. The `#[repr(u8)]`
/// discriminant is the wire `psk_id`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmPskId {
    /// Crypto Officer — PSK slot 0.
    CO = 0,
    /// Crypto User — PSK slot 1.
    CU = 1,
}

/// PSK credential for opening a security-domain session: the PSK slot
/// and, optionally, the caller's PSK.
///
/// When `psk` is `None`, the partition **default** PSK for the slot is
/// used — required for the first session, before the default PSK is
/// rotated. After rotation, pass the rotated secret via `psk`.
#[derive(Debug, Clone, Copy)]
pub struct HsmSessionPsk<'a> {
    /// PSK slot this session authenticates as.
    pub psk_id: HsmPskId,
    /// Caller-supplied PSK (exactly [`PSK_LEN`] bytes); `None` selects
    /// the partition default PSK for the slot.
    pub psk: Option<&'a [u8; PSK_LEN]>,
}

impl<'a> HsmSessionPsk<'a> {
    /// Opens the given slot with the partition **default** PSK — used
    /// for the first session, before the default PSK is rotated.
    pub fn new(psk_id: HsmPskId) -> Self {
        Self { psk_id, psk: None }
    }

    /// Opens the given slot with a caller-supplied (rotated) PSK.
    pub fn with_psk(psk_id: HsmPskId, psk: &'a [u8; PSK_LEN]) -> Self {
        Self {
            psk_id,
            psk: Some(psk),
        }
    }
}

/// Result of a security-domain partition-provisioning (`part_init_ex`)
/// command: the artifacts the device returns after initializing a
/// partition's security domain.
///
/// API-layer type with owned bytes. The DDI/wire response type
/// (`TborPartInitResp`) is converted into it inside the DDI layer, so the
/// wire type never surfaces to public callers.
#[derive(Debug, Clone, Default)]
pub struct HsmPartInitExResult {
    /// DER-encoded PKCS#10 CertificationRequest for the PTA public key.
    pub pta_csr: Vec<u8>,
    /// COSE_Sign1 PTA key-attestation report signed by the PID.
    pub pta_report: Vec<u8>,
}
