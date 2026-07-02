// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared [`HsmVaultKeyAttrs`] builders and request-validation
//! helpers used by every key-creating handler.
//!
//! The per-handler `for_*` builders translate the requested DDI
//! `key_metadata` bitflags into the firmware-side vault attribute
//! set the corresponding key kind is allowed to carry.  All builders
//! share the same skeleton — exactly one of the five usage flag
//! groups must be set, `local` is always implied for internally
//! created keys, and `session` is independent — but each one
//! enforces a per-algorithm policy on which usage(s) are valid.
//!
//! [`check_session_key_tag`] folds in the cross-cutting consistency
//! check that session-only keys cannot carry a host-supplied
//! `key_tag` (those keys are anonymous and not looked up across
//! sessions).

use azihsm_fw_ddi_mbor_types::DdiTargetKeyMetadata;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;

/// Build vault attrs for an internally-generated ECC private key.
///
/// ECC keys can sign / verify (matched pair) or derive (ECDH).
/// `encrypt_decrypt`, `unwrap`, and `wrap` are rejected with
/// [`HsmError::InvalidPermissions`].  `wrap` is folded into the
/// usage-count even though no curve currently allows it, so that
/// `sign+verify+wrap` is rejected as multi-usage rather than
/// silently treated as plain `sign+verify`.
///
/// The `curve` parameter is currently unused — all three NIST
/// curves accept the same usages — but kept in the signature so
/// future curve-specific tightening lands without a call-site
/// churn.
pub(crate) fn for_ecc(
    curve: HsmEccCurve,
    metadata: &DdiTargetKeyMetadata,
) -> HsmResult<HsmVaultKeyAttrs> {
    let _ = curve;
    validate_pairs(metadata)?;
    let mut attrs = HsmVaultKeyAttrs::new().with_local(true);

    let sign_verify = metadata.sign() && metadata.verify();
    let encrypt_decrypt = metadata.encrypt() && metadata.decrypt();
    let derive = metadata.derive();
    let unwrap = metadata.unwrap();
    let wrap = metadata.wrap();

    let usage_count = (sign_verify as u8)
        + (encrypt_decrypt as u8)
        + (derive as u8)
        + (unwrap as u8)
        + (wrap as u8);
    if usage_count != 1 {
        return Err(HsmError::InvalidPermissions);
    }

    if encrypt_decrypt || unwrap || wrap {
        return Err(HsmError::InvalidPermissions);
    }

    if sign_verify {
        attrs = attrs.with_sign(true).with_verify(true);
    }
    if derive {
        attrs = attrs.with_derive(true);
    }

    if metadata.session() {
        attrs = attrs.with_session(true);
    }

    Ok(attrs)
}

/// Build vault attrs for an internally-generated non-bulk AES key.
///
/// AES (non-bulk) keys can only carry `EncryptDecrypt`.  Any other
/// usage flag — sign, verify, derive, wrap, or unwrap — is rejected
/// with [`HsmError::InvalidPermissions`].
pub(crate) fn for_aes(metadata: &DdiTargetKeyMetadata) -> HsmResult<HsmVaultKeyAttrs> {
    validate_pairs(metadata)?;
    let mut attrs = HsmVaultKeyAttrs::new().with_local(true);

    let sign_verify = metadata.sign() && metadata.verify();
    let encrypt_decrypt = metadata.encrypt() && metadata.decrypt();
    let derive = metadata.derive();
    let wrap = metadata.wrap();
    let unwrap = metadata.unwrap();

    let usage_count = (sign_verify as u8)
        + (encrypt_decrypt as u8)
        + (derive as u8)
        + (wrap as u8)
        + (unwrap as u8);
    if usage_count != 1 {
        return Err(HsmError::InvalidPermissions);
    }

    if !encrypt_decrypt {
        return Err(HsmError::InvalidPermissions);
    }
    attrs = attrs.with_encrypt(true).with_decrypt(true);

    if metadata.session() {
        attrs = attrs.with_session(true);
    }

    Ok(attrs)
}

/// Build vault attrs for an ECDH-derived shared secret.
///
/// Derived secrets are HKDF / KBKDF inputs, so the only valid usage
/// is `derive` (PKCS#11 `CKA_DERIVE`).  Any other usage is rejected
/// with [`HsmError::InvalidPermissions`].
pub(crate) fn for_ecdh_secret(metadata: &DdiTargetKeyMetadata) -> HsmResult<HsmVaultKeyAttrs> {
    validate_pairs(metadata)?;
    let mut attrs = HsmVaultKeyAttrs::new().with_local(true);

    let sign_verify = metadata.sign() && metadata.verify();
    let encrypt_decrypt = metadata.encrypt() && metadata.decrypt();
    let derive = metadata.derive();
    let wrap = metadata.wrap();
    let unwrap = metadata.unwrap();

    let usage_count = (sign_verify as u8)
        + (encrypt_decrypt as u8)
        + (derive as u8)
        + (wrap as u8)
        + (unwrap as u8);
    if usage_count != 1 {
        return Err(HsmError::InvalidPermissions);
    }

    if !derive {
        return Err(HsmError::InvalidPermissions);
    }
    attrs = attrs.with_derive(true);

    if metadata.session() {
        attrs = attrs.with_session(true);
    }

    Ok(attrs)
}

/// Build vault attrs for a derived variable-length HMAC key.
///
/// HMAC keys produced by HKDF / KBKDF can sign / verify MACs or act
/// as a key-derivation key (`derive`) for a further KDF.  Exactly one
/// of those two usage groups must be set; `encrypt_decrypt`, `wrap`,
/// and `unwrap` are rejected with [`HsmError::InvalidPermissions`].
pub(crate) fn for_var_hmac(metadata: &DdiTargetKeyMetadata) -> HsmResult<HsmVaultKeyAttrs> {
    validate_pairs(metadata)?;
    let mut attrs = HsmVaultKeyAttrs::new().with_local(true);

    let sign_verify = metadata.sign() && metadata.verify();
    let encrypt_decrypt = metadata.encrypt() && metadata.decrypt();
    let derive = metadata.derive();
    let wrap = metadata.wrap();
    let unwrap = metadata.unwrap();

    let usage_count = (sign_verify as u8)
        + (encrypt_decrypt as u8)
        + (derive as u8)
        + (wrap as u8)
        + (unwrap as u8);
    if usage_count != 1 {
        return Err(HsmError::InvalidPermissions);
    }

    if encrypt_decrypt || wrap || unwrap {
        return Err(HsmError::InvalidPermissions);
    }

    if sign_verify {
        attrs = attrs.with_sign(true).with_verify(true);
    }
    if derive {
        attrs = attrs.with_derive(true);
    }

    if metadata.session() {
        attrs = attrs.with_session(true);
    }

    Ok(attrs)
}

/// Reject metadata where one half of a paired usage flag is set
/// without the other (`sign` without `verify`, or `encrypt`
/// without `decrypt`).  The host is supposed to encode these as
/// matched pairs; a half-set pair is either a malformed request
/// or an attempt to smuggle in a usage bit that would be silently
/// dropped by the `sign && verify` / `encrypt && decrypt` grouping
/// in the per-kind builders below.
fn validate_pairs(metadata: &DdiTargetKeyMetadata) -> HsmResult<()> {
    if metadata.sign() != metadata.verify() {
        return Err(HsmError::InvalidPermissions);
    }
    if metadata.encrypt() != metadata.decrypt() {
        return Err(HsmError::InvalidPermissions);
    }
    Ok(())
}

/// Reject a session-only key request that also carries a host-
/// supplied `key_tag`.  Session-only keys are anonymous and cannot
/// be looked up across sessions, so a tag is meaningless.
pub(crate) fn check_session_key_tag(
    attrs: HsmVaultKeyAttrs,
    key_tag: Option<u16>,
) -> HsmResult<()> {
    if attrs.session() && key_tag.is_some() {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}
