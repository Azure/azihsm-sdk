// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI wire → firmware-internal type conversions shared by handlers.
//!
//! Translates enums and other small types that arrive on the DDI
//! wire (host-facing) into their firmware-side counterparts (PAL
//! traits, vault kinds, internal flag sets).  Multiple handlers
//! share each mapping, so centralizing the conversions here keeps
//! the set of supported variants — and the error code used for
//! unsupported ones — consistent across all handlers.
//!
//! Functions are intentionally bare-named (`hash`, `curve`, …) so
//! call sites read as `from_ddi::hash(algo)` / `from_ddi::curve(c)`,
//! mirroring Rust's `From::from(value)` idiom.

use azihsm_fw_ddi_mbor_types::DdiAesKeySize;
use azihsm_fw_ddi_mbor_types::DdiEccCurve;
use azihsm_fw_ddi_mbor_types::DdiHashAlgorithm;
use azihsm_fw_ddi_mbor_types::DdiKeyType;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;

/// Map a [`DdiHashAlgorithm`] to its [`HsmHashAlgo`] counterpart.
/// Unsupported / unknown variants return [`HsmError::InvalidArg`].
pub(crate) fn hash(algo: DdiHashAlgorithm) -> HsmResult<HsmHashAlgo> {
    match algo {
        DdiHashAlgorithm::Sha1 => Ok(HsmHashAlgo::Sha1),
        DdiHashAlgorithm::Sha256 => Ok(HsmHashAlgo::Sha256),
        DdiHashAlgorithm::Sha384 => Ok(HsmHashAlgo::Sha384),
        DdiHashAlgorithm::Sha512 => Ok(HsmHashAlgo::Sha512),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Map a [`DdiEccCurve`] to its [`HsmEccCurve`] counterpart.
/// Unsupported / unknown variants return [`HsmError::InvalidArg`].
pub(crate) fn curve(curve: DdiEccCurve) -> HsmResult<HsmEccCurve> {
    match curve {
        DdiEccCurve::P256 => Ok(HsmEccCurve::P256),
        DdiEccCurve::P384 => Ok(HsmEccCurve::P384),
        DdiEccCurve::P521 => Ok(HsmEccCurve::P521),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Map a [`DdiAesKeySize`] to its raw byte length and the matching
/// non-bulk AES vault kind.  Bulk AES variants (XTS / GCM) are
/// rejected with [`HsmError::InvalidArg`] — handled by separate
/// future handlers.
pub(crate) fn aes(size: DdiAesKeySize) -> HsmResult<(usize, HsmVaultKeyKind)> {
    match size {
        DdiAesKeySize::Aes128 => Ok((16, HsmVaultKeyKind::Aes128)),
        DdiAesKeySize::Aes192 => Ok((24, HsmVaultKeyKind::Aes192)),
        DdiAesKeySize::Aes256 => Ok((32, HsmVaultKeyKind::Aes256)),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Map the on-wire [`DdiKeyType`] tag recorded in a masked-key blob's
/// metadata back to the [`HsmVaultKeyKind`] the key is re-imported as.
///
/// Public, internal, and non-maskable kinds return
/// [`HsmError::InvalidKeyType`].  [`DdiKeyType::RsaUnwrap`] is
/// intentionally rejected here — the partition unwrapping key must not
/// be re-imported as a general RSA key.
pub(crate) fn vault_kind_from_ddi(key_type: DdiKeyType) -> HsmResult<HsmVaultKeyKind> {
    match key_type {
        DdiKeyType::Rsa2kPrivate => Ok(HsmVaultKeyKind::Rsa2kPrivate),
        DdiKeyType::Rsa3kPrivate => Ok(HsmVaultKeyKind::Rsa3kPrivate),
        DdiKeyType::Rsa4kPrivate => Ok(HsmVaultKeyKind::Rsa4kPrivate),
        DdiKeyType::Rsa2kPrivateCrt => Ok(HsmVaultKeyKind::Rsa2kPrivateCrt),
        DdiKeyType::Rsa3kPrivateCrt => Ok(HsmVaultKeyKind::Rsa3kPrivateCrt),
        DdiKeyType::Rsa4kPrivateCrt => Ok(HsmVaultKeyKind::Rsa4kPrivateCrt),
        DdiKeyType::Ecc256Private => Ok(HsmVaultKeyKind::Ecc256Private),
        DdiKeyType::Ecc384Private => Ok(HsmVaultKeyKind::Ecc384Private),
        DdiKeyType::Ecc521Private => Ok(HsmVaultKeyKind::Ecc521Private),
        DdiKeyType::Aes128 => Ok(HsmVaultKeyKind::Aes128),
        DdiKeyType::Aes192 => Ok(HsmVaultKeyKind::Aes192),
        DdiKeyType::Aes256 => Ok(HsmVaultKeyKind::Aes256),
        DdiKeyType::AesXtsBulk256 => Ok(HsmVaultKeyKind::AesXtsBulk256),
        DdiKeyType::AesGcmBulk256 => Ok(HsmVaultKeyKind::AesGcmBulk256),
        DdiKeyType::AesGcmBulk256Unapproved => Ok(HsmVaultKeyKind::AesGcmBulk256Unapproved),
        DdiKeyType::Secret256 => Ok(HsmVaultKeyKind::Secret256),
        DdiKeyType::Secret384 => Ok(HsmVaultKeyKind::Secret384),
        DdiKeyType::Secret521 => Ok(HsmVaultKeyKind::Secret521),
        DdiKeyType::VarHmac256 => Ok(HsmVaultKeyKind::VarLenHmacSha256),
        DdiKeyType::VarHmac384 => Ok(HsmVaultKeyKind::VarLenHmacSha384),
        DdiKeyType::VarHmac512 => Ok(HsmVaultKeyKind::VarLenHmacSha512),
        _ => Err(HsmError::InvalidKeyType),
    }
}
