// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared [`HsmVaultKeyAttrs`] builders and request-validation
//! helpers used by every key-creating handler.
//!
//! The per-handler `for_*` builders translate the requested DDI
//! `key_metadata` bitflags into the firmware-side vault attribute
//! set the corresponding key kind is allowed to carry.  All builders
//! share the same skeleton — exactly one of the five usage flag
//! groups must be set, `local` reflects PKCS#11 `CKA_LOCAL` (set only for
//! on-device key *generation*, not derive / import), and `session` is
//! independent — but each
//! enforces a per-algorithm policy on which usage(s) are valid.
//!
//! [`check_session_key_tag`] folds in the cross-cutting consistency
//! check that session-only keys cannot carry a host-supplied
//! `key_tag` (those keys are anonymous and not looked up across
//! sessions).

use azihsm_fw_ddi_mbor_types::DdiTargetKeyMetadata;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;

/// Build vault attrs for an ECC private key.
///
/// `local` records provenance: `true` for a key generated on this device,
/// `false` for one imported (e.g. recovered via RsaUnwrap).
///
/// ECC keys can sign / verify (matched pair) or derive (ECDH).
/// `encrypt_decrypt`, `unwrap`, and `wrap` are rejected with
/// [`HsmError::InvalidPermissions`].  `wrap` is folded into the
/// usage-count even though no curve currently allows it, so that
/// `sign+verify+wrap` is rejected as multi-usage rather than
/// silently treated as plain `sign+verify`.
///
/// The accepted usages are curve-agnostic (all three NIST curves are
/// equivalent here), so no curve argument is taken; a future
/// curve-specific tightening would thread the resolved curve back in.
pub(crate) fn for_ecc(metadata: &DdiTargetKeyMetadata, local: bool) -> HsmResult<HsmVaultKeyAttrs> {
    validate_pairs(metadata)?;
    let mut attrs = HsmVaultKeyAttrs::new().with_local(local);

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

/// Build vault attrs for a non-bulk AES key.
///
/// `local` records provenance: `true` only for a key generated on this device,
/// `false` for derived and imported / unwrapped keys (e.g. recovered via RsaUnwrap).
///
/// AES (non-bulk) keys can only carry `EncryptDecrypt`.  Any other
/// usage flag — sign, verify, derive, wrap, or unwrap — is rejected
/// with [`HsmError::InvalidPermissions`].
pub(crate) fn for_aes(metadata: &DdiTargetKeyMetadata, local: bool) -> HsmResult<HsmVaultKeyAttrs> {
    validate_pairs(metadata)?;
    let mut attrs = HsmVaultKeyAttrs::new().with_local(local);

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

/// Build vault attrs for an RSA private key.
///
/// `local` records provenance: `true` for a key generated on this device,
/// `false` for one imported (e.g. recovered via RsaUnwrap).
///
/// RSA private keys carry exactly one usage — `SignVerify` or
/// `EncryptDecrypt` (the two RSA operations exposed by the DDI).  Any
/// other usage flag — derive, wrap, or unwrap — is rejected with
/// [`HsmError::InvalidPermissions`].
pub(crate) fn for_rsa(metadata: &DdiTargetKeyMetadata, local: bool) -> HsmResult<HsmVaultKeyAttrs> {
    validate_pairs(metadata)?;
    let mut attrs = HsmVaultKeyAttrs::new().with_local(local);

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

    if sign_verify {
        attrs = attrs.with_sign(true).with_verify(true);
    } else if encrypt_decrypt {
        attrs = attrs.with_encrypt(true).with_decrypt(true);
    } else {
        return Err(HsmError::InvalidPermissions);
    }

    if metadata.session() {
        attrs = attrs.with_session(true);
    }

    Ok(attrs)
}

/// Build vault attrs for an ECDH-derived shared secret.
///
/// The secret is *derived* (ECDH key agreement), so it is never marked
/// `local` — PKCS#11 sets `CKA_LOCAL` only for on-device key generation.
///
/// Derived secrets are HKDF / KBKDF inputs, so the only valid usage
/// is `derive` (PKCS#11 `CKA_DERIVE`).  Any other usage is rejected
/// with [`HsmError::InvalidPermissions`].
pub(crate) fn for_ecdh_secret(metadata: &DdiTargetKeyMetadata) -> HsmResult<HsmVaultKeyAttrs> {
    validate_pairs(metadata)?;
    let mut attrs = HsmVaultKeyAttrs::new().with_local(false);

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
/// These keys are *derived* (HKDF / KBKDF), so they are never marked
/// `local` — PKCS#11 sets `CKA_LOCAL` only for on-device key generation.
///
/// HMAC keys produced by HKDF / KBKDF can sign / verify MACs or act
/// as a key-derivation key (`derive`) for a further KDF.  Exactly one
/// of those two usage groups must be set; `encrypt_decrypt`, `wrap`,
/// and `unwrap` are rejected with [`HsmError::InvalidPermissions`].
pub(crate) fn for_var_hmac(metadata: &DdiTargetKeyMetadata) -> HsmResult<HsmVaultKeyAttrs> {
    validate_pairs(metadata)?;
    let mut attrs = HsmVaultKeyAttrs::new().with_local(false);

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
