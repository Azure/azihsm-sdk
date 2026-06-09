// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared logic for the HKDF / KBKDF key-derivation handlers
//! ([`hkdf_derive`](super::hkdf_derive) and
//! [`kbkdf_derive`](super::kbkdf_derive)).
//!
//! Both commands take the same shape — an input ECDH shared-secret
//! key (the IKM / KDK), an output `key_type` + optional `key_length`,
//! and target key properties — so the input validation and the
//! output target resolution are factored here to keep the two
//! handlers byte-for-byte consistent.
//!
//! ## Output storage policy
//!
//! Mirrors the reference firmware's `key_type` dispatch with one
//! deliberate divergence: **all HMAC outputs are stored as the
//! variable-length HMAC vault kind** ([`HsmVaultKeyKind::VarLenHmacSha256`]
//! etc.), never the deprecated fixed-length `_HmacSha*` kinds.  AES
//! outputs still map to the matching AES vault kind.
//!
//! | Requested `key_type` | Vault kind | Output length |
//! |---|---|---|
//! | `Aes128` / `Aes192` / `Aes256` | `Aes128` / `Aes192` / `Aes256` | 16 / 24 / 32 |
//! | `HmacSha256` / `384` / `512` | `VarLenHmacSha256` / `384` / `512` | 32 / 48 / 64 |
//! | `VarHmac256` / `384` / `512` | `VarLenHmacSha256` / `384` / `512` | `key_length` |
//!
//! Variable-length HMAC outputs require an explicit `key_length`
//! (absent → [`HsmError::InvalidKeyType`], matching the reference)
//! validated against the per-variant range (out of range →
//! [`HsmError::InvalidKeyLength`]):
//!
//! | Vault kind | min | max |
//! |---|---|---|
//! | `VarLenHmacSha256` | 32 | 64 |
//! | `VarLenHmacSha384` | 48 | 128 |
//! | `VarLenHmacSha512` | 64 | 128 |

use azihsm_fw_ddi_mbor_types::DdiKeyType;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;

/// Which attribute family the derived key is created with.
///
/// The KDF output's vault kind decides the permitted usage: AES keys
/// carry `encrypt`/`decrypt`, HMAC keys carry `sign`/`verify`.  The
/// handler selects the matching [`key_attrs`](super::key_attrs)
/// builder from this tag.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum KdfClass {
    /// AES key — `encrypt` / `decrypt` usage.
    Aes,
    /// (Variable-length) HMAC key — `sign` / `verify` usage.
    Hmac,
}

/// Resolved derivation target: where the OKM is stored and how many
/// bytes to derive.
pub(crate) struct KdfTarget {
    /// Vault kind the derived bytes are stored under.
    pub kind: HsmVaultKeyKind,
    /// Number of OKM bytes to derive.
    pub out_len: usize,
    /// Attribute family for the created key.
    pub class: KdfClass,
}

/// Reject an input key whose kind is not an ECDH shared secret.
///
/// HKDF / KBKDF derive from an ECDH shared secret (`Secret256` /
/// `Secret384` / `Secret521`); any other vault kind is rejected with
/// [`HsmError::InvalidKeyType`] — matching the reference firmware's
/// `ecdh_key(..)` lookup and the sim's input-kind check.
pub(crate) fn validate_input_secret(kind: HsmVaultKeyKind) -> HsmResult<()> {
    match kind {
        HsmVaultKeyKind::Secret256 | HsmVaultKeyKind::Secret384 | HsmVaultKeyKind::Secret521 => {
            Ok(())
        }
        _ => Err(HsmError::InvalidKeyType),
    }
}

/// Resolve the requested output `key_type` (+ optional `key_length`)
/// into the vault kind, OKM length, and attribute family.
///
/// See the [module docs](self) for the full mapping.  Unsupported
/// output types (ECC / RSA / Secret / bulk AES) return
/// [`HsmError::InvalidKeyType`].
pub(crate) fn resolve_target(key_type: DdiKeyType, key_len: Option<u8>) -> HsmResult<KdfTarget> {
    let aes = |kind, out_len| {
        Ok(KdfTarget {
            kind,
            out_len,
            class: KdfClass::Aes,
        })
    };
    let hmac = |kind, out_len| {
        Ok(KdfTarget {
            kind,
            out_len,
            class: KdfClass::Hmac,
        })
    };

    match key_type {
        DdiKeyType::Aes128 => aes(HsmVaultKeyKind::Aes128, 16),
        DdiKeyType::Aes192 => aes(HsmVaultKeyKind::Aes192, 24),
        DdiKeyType::Aes256 => aes(HsmVaultKeyKind::Aes256, 32),

        DdiKeyType::HmacSha256 => hmac(HsmVaultKeyKind::VarLenHmacSha256, 32),
        DdiKeyType::HmacSha384 => hmac(HsmVaultKeyKind::VarLenHmacSha384, 48),
        DdiKeyType::HmacSha512 => hmac(HsmVaultKeyKind::VarLenHmacSha512, 64),

        DdiKeyType::VarHmac256 => hmac(
            HsmVaultKeyKind::VarLenHmacSha256,
            var_hmac_len(key_len, 32, 64)?,
        ),
        DdiKeyType::VarHmac384 => hmac(
            HsmVaultKeyKind::VarLenHmacSha384,
            var_hmac_len(key_len, 48, 128)?,
        ),
        DdiKeyType::VarHmac512 => hmac(
            HsmVaultKeyKind::VarLenHmacSha512,
            var_hmac_len(key_len, 64, 128)?,
        ),

        _ => Err(HsmError::InvalidKeyType),
    }
}

/// Validate a variable-length HMAC `key_length`.
///
/// A missing length is [`HsmError::InvalidKeyType`] (the reference
/// firmware's sentinel for "var-len HMAC without an explicit
/// length"); an out-of-range length is [`HsmError::InvalidKeyLength`].
fn var_hmac_len(key_len: Option<u8>, min: usize, max: usize) -> HsmResult<usize> {
    let len = usize::from(key_len.ok_or(HsmError::InvalidKeyType)?);
    if len < min || len > max {
        return Err(HsmError::InvalidKeyLength);
    }
    Ok(len)
}
