// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_int;

use api_interface::REPORT_DATA_SIZE;
use engine_common::handle_table::Handle;
use mcr_api::*;
use openssl_rust::safeapi::ec::key::EcKey;
use openssl_rust::safeapi::error::*;
use openssl_rust::safeapi::evp_md::ctx::EvpMdCtx;
use openssl_rust::safeapi::evp_md::md::EvpMdType;
use openssl_rust::safeapi::evp_pkey::callback::common::SignCtxResult;
use openssl_rust::safeapi::evp_pkey::callback::ec::*;
use openssl_rust::safeapi::evp_pkey::ctx::EvpPKeyCtx;
use openssl_rust::safeapi::evp_pkey::pkey::EvpPKey;
use openssl_rust::EVP_MD_CTX;
use openssl_rust::EVP_MD_CTX_FLAG_FINALISE;
use openssl_rust::EVP_PKEY;
use openssl_rust::EVP_PKEY_CTX;

use crate::common::base_key::Key;
use crate::common::base_key::ENGINE_KEY_HANDLE_TABLE;
use crate::common::ec_key::*;
use crate::common::hash::azihsm_hash_type;
use crate::common::hash::openssl_hash_nid;
use crate::common::hsm_key::HsmKeyContainer;
use crate::ec::callback::ec_attest_key;
use crate::get_or_create_keydata;

pub(crate) fn pkey_ec_import_key(
    ctx_ptr: *mut EVP_PKEY_CTX,
    curve_name: i32,
    wrapped_blob: &[u8],
    digest_kind: DigestKind,
    key_usage: KeyUsage,
    key_availability: KeyAvailability,
    key_name: Option<u16>,
) -> OpenSSLResult<()> {
    let key_container = HsmKeyContainer::unwrap_key(
        wrapped_blob.to_vec(),
        KeyClass::Ecc,
        digest_kind,
        key_usage,
        key_availability,
        key_name,
    )?;

    let ctx: EvpPKeyCtx<EcKeyData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    let ctx_ec_keydata = get_or_create_keydata!(ctx, EcKeyData)?;
    ctx_ec_keydata.set_curve(curve_name)?;

    if let Some(mut cur_ec_key) = ctx.ec_key_from_pkey() {
        tracing::info!("pkey_ec_import_key. Freeing existing ec key");
        cur_ec_key.free_data();
    }

    let ctx_pkey = ctx.get_evp_pkey()?;
    pkey_assign_ec_key(&ctx, &ctx_pkey)?;

    let ec_key_ptr = ctx_pkey.ec_key()?;
    let mut ec_key: EcKey<EcKeyData> = EcKey::new_from_ptr(ec_key_ptr);
    let ec_keydata = ec_key.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;

    ec_keydata.set_imported_key(key_container);
    ec_keydata.set_key_type(key_usage == KeyUsage::Derive);
    let pub_key = ec_keydata.export_public_key()?;
    ec_key.set_pubkey_der(pub_key)
}

/// Open the given HSM private key by name
///
/// # Arguments
/// * `key_container` - Container of the opened key
/// * `is_derive` - Whether or not this key is usable in ECDH
///
/// # Returns
/// * `OpenSSLResult<EvpPKey>` - An `EvpPKey` with the key data
pub(crate) fn pkey_ec_open_private_key(
    key_container: HsmKeyContainer,
    is_derive: bool,
) -> OpenSSLResult<EvpPKey> {
    let curve_type = EcCurveType::try_from(key_container.key_kind())?;

    let pub_key = key_container.export_public_key()?;

    // Create new EC key data
    let ec_keydata = EcKeyData::new();
    ec_keydata.set_imported_key(key_container);
    ec_keydata.set_key_type(is_derive);
    ec_keydata.set_curve(curve_type.to_curve_name())?;

    // Create a new EcKey object and set the group and pubkey
    let mut ec_key: EcKey<EcKeyData> = EcKey::new()?;
    ec_key
        .set_key_group_by_name(curve_type.to_curve_name())
        .inspect_err(|_| {
            ec_key.free();
        })?;
    ec_key.set_pubkey_der(pub_key).inspect_err(|_| {
        ec_key.free();
    })?;
    ec_key.set_data(ec_keydata).inspect_err(|_| {
        ec_key.free();
    })?;

    // Assign EC key with data attached to the EVP_PKEY
    let mut pkey = EvpPKey::new_unowned().inspect_err(|_| {
        ec_key.free();
    })?;
    pkey.assign_ec_key(ec_key.as_mut_ptr()).inspect_err(|_| {
        pkey.free();
        ec_key.free();
    })?;

    Ok(pkey)
}

/// EC Key attest callback for attesting the key in `EVP_PKEY` format
///
/// # Arguments
/// * `pkey_ptr` - A pointer to the `EVP_PKEY` initialized with the `EC_KEY` object.
/// * `report_data` - The report data to be attested.
///
/// # Returns
/// Result of the attest operation.
pub(crate) fn pkey_ec_attest_key(
    pkey_ptr: *mut EVP_PKEY,
    report_data: &[u8; REPORT_DATA_SIZE as usize],
) -> OpenSSLResult<Vec<u8>> {
    let pkey = EvpPKey::new_from_ptr(pkey_ptr);
    ec_attest_key(pkey.ec_key()?, report_data)
}

/// EC copy callback
/// This function is called whenever the PKey context is copied for EVP_PKEY_EC algorithm.
///
/// # Arguments
/// * `dst_ptr` - A pointer to the destination `EVP_PKEY_CTX` object.
/// * `src_ptr` - A pointer to the source `EVP_PKEY_CTX` object.
///
/// # Returns
/// Result of the copy operation.
#[allow(unused)]
pub(crate) fn ec_copy_cb(
    dst_ptr: *mut EVP_PKEY_CTX,
    src_ptr: *const EVP_PKEY_CTX,
) -> OpenSSLResult<()> {
    let src_ctx: EvpPKeyCtx<EcKeyData> = EvpPKeyCtx::new_from_ptr(src_ptr as *mut EVP_PKEY_CTX);
    let dst_ctx: EvpPKeyCtx<EcKeyData> = EvpPKeyCtx::new_from_ptr(dst_ptr);
    let src_keydata = src_ctx.get_data().ok_or(OpenSSLError::InvalidKeyData)?;

    let mut dst_keydata = EcKeyData::new();
    dst_keydata.copy_param_from(src_keydata);
    dst_ctx.set_data(dst_keydata);

    if let (Some(src_ec_key), Some(mut dst_ec_key)) =
        (src_ctx.ec_key_from_pkey(), dst_ctx.ec_key_from_pkey())
    {
        let src_ec_keydata = src_ec_key.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;
        // Copy the key data from the source to the destination
        let mut dst_ec_keydata = src_ec_keydata.clone();
        dst_ec_key.reset_data()?;
        dst_ec_key.set_data(dst_ec_keydata)?;
    }

    Ok(())
}

/// EC paramgen init callback
///
/// # Arguments
/// * `ctx_ptr` - A pointer to the `EVP_PKEY_CTX` object.
///
/// # Returns
/// Result of the paramgen-init operation.
pub(crate) fn ec_paramgen_init_cb(ctx_ptr: *mut EVP_PKEY_CTX) -> OpenSSLResult<()> {
    let ctx: EvpPKeyCtx<EcKeyData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    let ec_keydata = get_or_create_keydata!(ctx, EcKeyData)?;
    ec_keydata.param_init();

    Ok(())
}

/// EC paramgen callback
///
/// # Arguments
/// * `ctx_ptr` - A pointer to the `EVP_PKEY_CTX` object.
/// * `pkey_ptr` - A pointer to the `EVP_PKEY` object.
///
/// # Returns
/// Result of the paramgen operation.
pub(crate) fn ec_paramgen_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    pkey_ptr: *mut EVP_PKEY,
) -> OpenSSLResult<()> {
    let ctx: EvpPKeyCtx<EcKeyData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);

    let pkey = EvpPKey::new_from_ptr(pkey_ptr);
    pkey_assign_ec_key(&ctx, &pkey)
}

/// EC Keygen/Derive/SignVerify init callback
///
/// # Arguments
/// * `ctx_ptr` - A pointer to the `EVP_PKEY_CTX` object.
///
/// # Returns
/// Result of the keygen-init operation.
pub(crate) fn ec_op_init(ctx_ptr: *mut EVP_PKEY_CTX) -> OpenSSLResult<()> {
    let ctx: EvpPKeyCtx<EcKeyData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    get_or_create_keydata!(ctx, EcKeyData)?;

    Ok(())
}

/// EC keygen callback
///
/// # Arguments
/// * `ctx_ptr` - A pointer to the `EVP_PKEY_CTX` object.
/// * `pkey_ptr` - A pointer to the `EVP_PKEY` object.
///
/// # Returns
/// Result of the keygen operation.
pub(crate) fn ec_keygen_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    pkey_ptr: *mut EVP_PKEY,
) -> OpenSSLResult<()> {
    let ctx: EvpPKeyCtx<EcKeyData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    let ctx_keydata = ctx.get_data().ok_or(OpenSSLError::InvalidKeyData)?;

    if ctx_keydata.curve_type().is_none() {
        let ctx_ec_key = ctx
            .ec_key_from_pkey()
            .ok_or(OpenSSLError::EcMissingCurveName)?;
        let curve_name = ctx_ec_key.curve_name()?;
        ctx_keydata.set_curve(curve_name)?;
    };

    let pkey = EvpPKey::new_from_ptr(pkey_ptr);
    pkey_assign_ec_key(&ctx, &pkey)?;

    if let Ok(ctx_pkey) = ctx.get_evp_pkey() {
        pkey.copy_parameters(&ctx_pkey)?;
    }

    let ec_key_ptr = pkey.ec_key()?;
    let mut ec_key: EcKey<EcKeyData> = EcKey::new_from_ptr(ec_key_ptr);
    let ec_keydata = ec_key.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;

    ec_keydata.generate_key()?;
    let pub_key = ec_keydata.export_public_key()?;
    ec_key.set_pubkey_der(pub_key)
}

/// EC derive callback to compute shared secret.
/// A valid pkey and corresponding hsm private key handle should be present in the ctx
/// to compute the shared secret.
///
/// # Arguments
/// * `ctx_ptr` - A pointer to the `EVP_PKEY_CTX` object.
///
/// # Returns
/// Returns secret handle on success or error on failure.
pub(crate) fn ec_derive_cb(ctx_ptr: *mut EVP_PKEY_CTX) -> OpenSSLResult<Handle> {
    let ctx: EvpPKeyCtx<EcKeyData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    pkey_check_and_set_peerkey(&ctx)?;

    let ec_key: EcKey<EcKeyData> = ctx.ec_key_from_pkey().ok_or(OpenSSLError::InvalidKey)?;
    let ec_keydata = ec_key.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;

    let ecdh_secret = ec_keydata.compute_shared_secret()?;
    let handle = ENGINE_KEY_HANDLE_TABLE.insert_key(Key::Secret(ecdh_secret));
    Ok(handle)
}

/// EC cleanup callback
/// This function is called whenever the PKey context is cleaned up for `EVP_PKEY_EC` algorithm.
///
/// # Arguments
/// * `ctx_ptr` - A pointer to the `EVP_PKEY_CTX` object.
pub(crate) fn ec_cleanup_cb(ctx_ptr: *mut EVP_PKEY_CTX) {
    let ctx: EvpPKeyCtx<EcKeyData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    ctx.free_data();
}

/// EC ctrl callback
///
/// # Arguments
/// * `ctx_ptr` - A pointer to the `EVP_PKEY_CTX` object.
/// * `op` - The operation to be performed.
///
/// # Returns
/// Result of the operation.
pub(crate) fn ec_ctrl_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    op: EcCtrlOp,
) -> OpenSSLResult<Option<EcCtrlOpResult>> {
    let ctx: EvpPKeyCtx<EcKeyData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    let ec_keydata = ctx.get_data().ok_or(OpenSSLError::InvalidKeyData)?;
    match op {
        EcCtrlOp::SetMd(nid) => {
            ec_keydata.set_hash_type(azihsm_hash_type(nid)?);
            Ok(None)
        }
        EcCtrlOp::GetMd => Ok(Some(EcCtrlOpResult::GetMd(openssl_hash_nid(
            ec_keydata.get_hash_type(),
        )))),
        EcCtrlOp::DigestInit => Ok(None), // Default is okay
        EcCtrlOp::ParamgenCurveNid(curve_name) => {
            ec_keydata.set_curve(curve_name)?;
            Ok(None)
        }
        EcCtrlOp::KeyUsageEcdh => {
            ec_keydata.set_key_type(true);
            Ok(None)
        }
        EcCtrlOp::PeerKey(peer_key_ptr) => {
            pkey_set_peer_key(&ctx, peer_key_ptr)?;
            Ok(None)
        }
    }
}

/// EC signctx/verifyctx init callback for signing/verifying a digest
///
/// # Arguments
/// * `ctx_ptr` - A pointer to the `EVP_PKEY_CTX` object.
/// * `md_ctx_ptr` - A pointer to the `EVP_MD_CTX` object.
///
/// # Returns
/// Nothing or error.
pub(crate) fn ec_sign_verify_ctx_init_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    md_ctx_ptr: *mut EVP_MD_CTX,
) -> OpenSSLResult<()> {
    ec_op_init(ctx_ptr)?;

    let md_ctx = EvpMdCtx::new_from_ptr(md_ctx_ptr);
    md_ctx.set_flag(EVP_MD_CTX_FLAG_FINALISE as c_int);

    Ok(())
}

/// EC sign callback for signing the digest
/// A valid pkey and corresponding hsm private key handle should be present in the ctx
/// to sign the digest.
///
/// # Arguments
/// * `ctx_ptr` - A pointer to the `EVP_PKEY_CTX` object.
/// * `dgst` - The digest to be signed.
///
/// # Returns
/// Result of the sign operation.
pub(crate) fn ec_sign_cb(ctx_ptr: *mut EVP_PKEY_CTX, dgst: &[u8]) -> OpenSSLResult<Vec<u8>> {
    let ctx: EvpPKeyCtx<EcKeyData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    let ec_key: EcKey<EcKeyData> = ctx.ec_key_from_pkey().ok_or(OpenSSLError::InvalidKey)?;
    let ec_keydata = ec_key.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;
    ec_keydata.sign(dgst.to_vec())
}

/// EC signctx callback
/// This function is called when we do a signctx operation
///
/// # Arguments
/// * `ctx_ptr` - The `EVP_PKEY_CTX` context
/// * `md_ctx` - The `EVP_MD_CTX` context
/// * `get_siglen` - Whether or not to return the signature length
///
/// # Returns
/// The result of the signing operation
pub(crate) fn ec_signctx_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    md_ctx: *mut EVP_MD_CTX,
    get_siglen: bool,
) -> OpenSSLResult<SignCtxResult> {
    let ctx: EvpPKeyCtx<EcKeyData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    let ec_key: EcKey<EcKeyData> = ctx.ec_key_from_pkey().ok_or(OpenSSLError::InvalidKey)?;
    let ec_keydata = ec_key.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;

    if get_siglen {
        let sig_len = ec_keydata.sig_len()?;
        Ok(SignCtxResult::SigLen(sig_len))
    } else {
        let md = EvpMdCtx::new_from_ptr(md_ctx);
        let digest = md.digest_final()?;
        let sig = ec_sign_cb(ctx_ptr, digest.as_slice())?;
        Ok(SignCtxResult::Sig(sig))
    }
}

/// EC verify callback for verifying the signature
/// A valid pkey and corresponding hsm private key handle should be present in the ctx
/// to verify the signature.
///
/// # Arguments
/// * `ctx_ptr` - A pointer to the `EVP_PKEY_CTX` object.
/// * `sig` - The signature to be verified.
/// * `dgst` - The digest to be verified.
///
/// # Returns
/// Result of the verify operation.
pub(crate) fn ec_verify_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    sig: &[u8],
    dgst: &[u8],
) -> OpenSSLResult<()> {
    let ctx: EvpPKeyCtx<EcKeyData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    let ec_key: EcKey<EcKeyData> = ctx.ec_key_from_pkey().ok_or(OpenSSLError::InvalidKey)?;
    let ec_keydata = ec_key.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;
    ec_keydata.verify(dgst.to_vec(), sig.to_vec())
}

/// EC verifyctx callback
/// This function is called when we do a verifyctx operation
///
/// # Arguments
/// * `ctx_ptr` - The `EVP_PKEY_CTX` context
/// * `sig` - The signature to verify
/// * `md_ctx` - The `EVP_MD_CTX` context
///
/// # Returns
/// The result of the signing operation
pub(crate) fn ec_verifyctx_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    sig: &[u8],
    md_ctx: *mut EVP_MD_CTX,
) -> OpenSSLResult<()> {
    let md = EvpMdCtx::new_from_ptr(md_ctx);
    let hash_type = match md.get_md_type()? {
        EvpMdType::Sha1 => DigestKind::Sha1,
        EvpMdType::Sha256 => DigestKind::Sha256,
        EvpMdType::Sha384 => DigestKind::Sha384,
        EvpMdType::Sha512 => DigestKind::Sha512,
    };

    let ctx: EvpPKeyCtx<EcKeyData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    let ec_key: EcKey<EcKeyData> = ctx.ec_key_from_pkey().ok_or(OpenSSLError::InvalidKey)?;
    let ec_keydata = ec_key.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;
    let hash_type_old = ec_keydata.get_hash_type();
    ec_keydata.set_hash_type(Some(hash_type));

    let digest = md.digest_final()?;
    let result = ec_verify_cb(ctx_ptr, sig, &digest);
    ec_keydata.set_hash_type(hash_type_old);
    result
}

/// It's not necessary to initialize the ctx with the pkey to set the peer key.
/// If the pkey hasn't been set in the ctx yet, then the peer key will be stored in the ctx's keydata.
fn pkey_set_peer_key(
    ctx: &EvpPKeyCtx<EcKeyData>,
    peer_key_ptr: *mut EVP_PKEY,
) -> OpenSSLResult<()> {
    let peer_pkey = EvpPKey::new_from_ptr(peer_key_ptr);
    let peer_ec_key_ptr = peer_pkey.ec_key()?;
    let peer_ec_key: EcKey<EcKeyData> = EcKey::new_from_ptr(peer_ec_key_ptr);
    let peer_pubkey_der = peer_ec_key.get_pubkey_der()?;

    if let Some(ec_key) = ctx.ec_key_from_pkey() {
        let ec_keydata = ec_key.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;
        ec_keydata.set_peer_key(peer_pubkey_der);
    } else {
        let ctx_keydata = ctx.get_data().ok_or(OpenSSLError::InvalidKeyData)?;
        ctx_keydata.set_peer_key(peer_pubkey_der);
    }
    Ok(())
}

/// If peer key is not set in the ec keydata, try copying it from the ctx's keydata if it's present.
fn pkey_check_and_set_peerkey(ctx: &EvpPKeyCtx<EcKeyData>) -> OpenSSLResult<()> {
    let ctx_ec_key = ctx.ec_key_from_pkey().ok_or(OpenSSLError::InvalidKey)?;
    let ctx_ec_keydata = ctx_ec_key.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;

    if ctx_ec_keydata.peer_key().is_none() {
        let ec_ketdata = ctx.get_data().ok_or(OpenSSLError::InvalidKeyData)?;
        let peer_key = ec_ketdata.peer_key().ok_or(OpenSSLError::InvalidKey)?;
        ctx_ec_keydata.set_peer_key(peer_key.to_vec());
    }

    Ok(())
}

/// Create a new EcKey object, initialize it and assign it to the pkey
fn pkey_assign_ec_key(ctx: &EvpPKeyCtx<EcKeyData>, pkey: &EvpPKey) -> OpenSSLResult<()> {
    let ctx_keydata = ctx.get_data().ok_or(OpenSSLError::InvalidKeyData)?;

    let curve_type = ctx_keydata
        .curve_type()
        .ok_or(OpenSSLError::EcMissingCurveName)?;

    // Create a new EcKey object and copy the parameters from the ctx keydata
    let mut ec_key: EcKey<EcKeyData> = EcKey::new()?;

    // set ec group
    ec_key
        .set_key_group_by_name(curve_type.to_curve_name())
        .inspect_err(|_| {
            ec_key.free();
        })?;

    let key_data = EcKeyData::new();
    key_data.copy_param_from(ctx_keydata);
    ec_key.set_data(key_data)?;

    // Assign the ec key to the pkey
    pkey.assign_ec_key(ec_key.as_mut_ptr())
}

#[cfg(test)]
mod tests {
    use openssl_rust::safeapi::engine::Engine;
    use openssl_rust::safeapi::evp_md::md::EvpMd;
    use openssl_rust::safeapi::evp_md::md::EvpMdType;
    use openssl_rust::safeapi::evp_pkey::method::EvpPKeyType;
    use openssl_rust::NID_X9_62_prime256v1;
    use openssl_rust::NID_secp384r1;
    use openssl_rust::NID_secp521r1;
    use openssl_rust::NID_sect113r1;

    use super::*;
    use crate::load_engine;

    type TestResult<T> = Result<T, &'static str>;

    fn check_param_init(pkey_ctx: &EvpPKeyCtx<EcKeyData>) -> TestResult<()> {
        let ec_keydata = pkey_ctx.get_data().expect("Could not get data");

        assert!(ec_keydata.curve_type().is_none());
        assert!(!ec_keydata.is_ecdh_key());
        assert!(ec_keydata.peer_key().is_none());
        Ok(())
    }

    fn check_op_init(pkey_ctx: &EvpPKeyCtx<EcKeyData>, ecdh: bool) -> TestResult<()> {
        let ec_keydata = pkey_ctx.get_data().expect("Could not get data");

        assert!(ec_keydata.curve_type().is_some());
        assert!(ec_keydata.is_ecdh_key() == ecdh);
        assert!(ec_keydata.peer_key().is_none());
        Ok(())
    }

    #[test]
    fn test_paramgen_init() {
        let e = load_engine();
        let pkey_ctx = create_ec_pkey_ctx(&e);
        assert!(ec_paramgen_init_cb(pkey_ctx.as_mut_ptr()).is_ok());
        assert!(check_param_init(&pkey_ctx).is_ok());
    }

    #[test]
    fn test_set_wrong_curve() {
        let e = load_engine();
        let pkey_ctx = create_ec_pkey_ctx(&e);
        assert!(ec_paramgen_init_cb(pkey_ctx.as_mut_ptr()).is_ok());
        assert!(check_param_init(&pkey_ctx).is_ok());

        let result = ec_ctrl_cb(
            pkey_ctx.as_mut_ptr(),
            EcCtrlOp::ParamgenCurveNid(NID_sect113r1 as i32),
        );
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_gen_no_curve() {
        let e = load_engine();
        assert!(verify_gen_no_curve(&e, false).is_ok());
        assert!(verify_gen_no_curve(&e, true).is_ok());
    }

    #[test]
    fn test_paramgen() {
        let e = load_engine();
        let param_p256 = verify_gen(&e, NID_X9_62_prime256v1, false, false);
        assert!(param_p256.is_ok());

        let param_p384 = verify_gen(&e, NID_secp384r1, false, false);
        assert!(param_p384.is_ok());

        let param_p521 = verify_gen(&e, NID_secp521r1, false, false);
        assert!(param_p521.is_ok());
    }

    #[test]
    fn test_keygen_with_curve_name() {
        let e = load_engine();
        // P-256 for ecdsa
        let ecdsa_pkey_p256 = verify_gen(&e, NID_X9_62_prime256v1, true, false);
        assert!(ecdsa_pkey_p256.is_ok());
        // P-256 for ecdh
        let ecdh_pkey_p256 = verify_gen(&e, NID_X9_62_prime256v1, true, true);
        assert!(ecdh_pkey_p256.is_ok());

        // P-384 for ecdsa
        let ecdsa_pkey_p384 = verify_gen(&e, NID_secp384r1, true, false);
        assert!(ecdsa_pkey_p384.is_ok());
        // P-384 for ecdh
        let ecdh_pkey_p384 = verify_gen(&e, NID_secp384r1, true, true);
        assert!(ecdh_pkey_p384.is_ok());

        // P-521 for ecdsa
        let ecdsa_pkey_p521 = verify_gen(&e, NID_secp521r1, true, false);
        assert!(ecdsa_pkey_p521.is_ok());
        // P-521 for ecdh
        let ecdh_pkey_p521 = verify_gen(&e, NID_secp521r1, true, true);
        assert!(ecdh_pkey_p521.is_ok());
    }

    #[test]
    fn test_keygen_with_pkey() {
        let e = load_engine();
        // P-256 for ecdsa
        let ecdsa_param_p256 =
            verify_gen(&e, NID_X9_62_prime256v1, false, false).expect("Could not generate param");
        assert!(verify_keygen_from_param(&e, ecdsa_param_p256, false).is_ok());

        // P-256 for ecdh
        let ecdh_param_p256 =
            verify_gen(&e, NID_X9_62_prime256v1, false, true).expect("Could not generate param");
        assert!(verify_keygen_from_param(&e, ecdh_param_p256, true).is_ok());

        // P-384 for ecdsa
        let ecdsa_param_p384 =
            verify_gen(&e, NID_secp384r1, false, false).expect("Could not generate param");
        assert!(verify_keygen_from_param(&e, ecdsa_param_p384, false).is_ok());

        // P-384 for ecdh
        let ecdh_param_p384 =
            verify_gen(&e, NID_secp384r1, false, true).expect("Could not generate param");
        assert!(verify_keygen_from_param(&e, ecdh_param_p384, true).is_ok());

        // P-521 for ecdsa
        let ecdsa_param_p521 =
            verify_gen(&e, NID_secp521r1, false, false).expect("Could not generate param");
        assert!(verify_keygen_from_param(&e, ecdsa_param_p521, false).is_ok());

        // P-521 for ecdh
        let ecdh_param_p521 =
            verify_gen(&e, NID_secp521r1, false, true).expect("Could not generate param");
        assert!(verify_keygen_from_param(&e, ecdh_param_p521, true).is_ok());
    }

    #[test]
    fn test_pkey_ecdh_compute_secret() {
        let e = load_engine();

        assert!(verify_ecdh_compute_secret(&e, NID_X9_62_prime256v1).is_ok());
        assert!(verify_ecdh_compute_secret(&e, NID_secp384r1).is_ok());
        assert!(verify_ecdh_compute_secret(&e, NID_secp521r1).is_ok());
    }

    #[test]
    fn test_pkey_ecdsa_sign_verify() {
        let e = load_engine();
        assert!(pkey_test_ecdsa(&e, NID_X9_62_prime256v1, 20, 64).is_ok());
        assert!(pkey_test_ecdsa(&e, NID_X9_62_prime256v1, 32, 64).is_ok());
        assert!(pkey_test_ecdsa(&e, NID_secp384r1, 20, 96).is_ok());
        assert!(pkey_test_ecdsa(&e, NID_secp384r1, 32, 96).is_ok());
        assert!(pkey_test_ecdsa(&e, NID_secp384r1, 48, 96).is_ok());
        assert!(pkey_test_ecdsa(&e, NID_secp521r1, 20, 132).is_ok());
        assert!(pkey_test_ecdsa(&e, NID_secp521r1, 32, 132).is_ok());
        assert!(pkey_test_ecdsa(&e, NID_secp521r1, 48, 132).is_ok());
        assert!(pkey_test_ecdsa(&e, NID_secp521r1, 64, 132).is_ok());
    }

    #[test]
    fn test_pkey_ecdsa_sign_verify_ctx() {
        let e = load_engine();
        assert!(pkey_test_ecdsa_ctx(&e, NID_X9_62_prime256v1, EvpMdType::Sha1, 64).is_ok());
        assert!(pkey_test_ecdsa_ctx(&e, NID_X9_62_prime256v1, EvpMdType::Sha256, 64).is_ok());
        assert!(pkey_test_ecdsa_ctx(&e, NID_secp384r1, EvpMdType::Sha1, 96).is_ok());
        assert!(pkey_test_ecdsa_ctx(&e, NID_secp384r1, EvpMdType::Sha256, 96).is_ok());
        assert!(pkey_test_ecdsa_ctx(&e, NID_secp384r1, EvpMdType::Sha384, 96).is_ok());
        assert!(pkey_test_ecdsa_ctx(&e, NID_secp521r1, EvpMdType::Sha1, 132).is_ok());
        assert!(pkey_test_ecdsa_ctx(&e, NID_secp521r1, EvpMdType::Sha256, 132).is_ok());
        assert!(pkey_test_ecdsa_ctx(&e, NID_secp521r1, EvpMdType::Sha384, 132).is_ok());
        assert!(pkey_test_ecdsa_ctx(&e, NID_secp521r1, EvpMdType::Sha512, 132).is_ok());
    }

    #[test]
    fn test_pkey_attest_key() {
        let e = load_engine();
        let report_data = [1u8; REPORT_DATA_SIZE as usize];

        // P-256 for ecdsa
        let ecdsa_pkey_p256 = verify_gen(&e, NID_X9_62_prime256v1, true, false);
        assert!(ecdsa_pkey_p256.is_ok());
        let claim_p256 = pkey_ec_attest_key(ecdsa_pkey_p256.unwrap().as_mut_ptr(), &report_data)
            .expect("Could not attest key");
        assert!(!claim_p256.is_empty());

        // P-256 for ecdh
        let ecdh_pkey_p256 = verify_gen(&e, NID_X9_62_prime256v1, true, true);
        assert!(ecdh_pkey_p256.is_ok());
        let claim_p256 = pkey_ec_attest_key(ecdh_pkey_p256.unwrap().as_mut_ptr(), &report_data)
            .expect("Could not attest key");
        assert!(!claim_p256.is_empty());

        // P-384 for ecdsa
        let ecdsa_pkey_p384 = verify_gen(&e, NID_secp384r1, true, false);
        assert!(ecdsa_pkey_p384.is_ok());
        let claim_p384 = pkey_ec_attest_key(ecdsa_pkey_p384.unwrap().as_mut_ptr(), &report_data)
            .expect("Could not attest key");
        assert!(!claim_p384.is_empty());

        // P-384 for ecdh
        let ecdh_pkey_p384 = verify_gen(&e, NID_secp384r1, true, true);
        assert!(ecdh_pkey_p384.is_ok());
        let claim_p384 = pkey_ec_attest_key(ecdh_pkey_p384.unwrap().as_mut_ptr(), &report_data)
            .expect("Could not attest key");
        assert!(!claim_p384.is_empty());

        // P-521 for ecdsa
        let ecdsa_pkey_p521 = verify_gen(&e, NID_secp521r1, true, false);
        assert!(ecdsa_pkey_p521.is_ok());
        let claim_p521 = pkey_ec_attest_key(ecdsa_pkey_p521.unwrap().as_mut_ptr(), &report_data)
            .expect("Could not attest key");
        assert!(!claim_p521.is_empty());

        // P-521 for ecdh
        let ecdh_pkey_p521 = verify_gen(&e, NID_secp521r1, true, true);
        assert!(ecdh_pkey_p521.is_ok());
        let claim_p521 = pkey_ec_attest_key(ecdh_pkey_p521.unwrap().as_mut_ptr(), &report_data)
            .expect("Could not attest key");
        assert!(!claim_p521.is_empty());
    }

    #[test]
    fn test_pkey_ctx_copy_ecdsa() {
        let e = load_engine();
        assert!(verify_pkey_ctx_copy_ecdsa(&e, NID_X9_62_prime256v1, 20, 64).is_ok());
        assert!(verify_pkey_ctx_copy_ecdsa(&e, NID_X9_62_prime256v1, 32, 64).is_ok());
        assert!(verify_pkey_ctx_copy_ecdsa(&e, NID_secp384r1, 20, 96).is_ok());
        assert!(verify_pkey_ctx_copy_ecdsa(&e, NID_secp384r1, 32, 96).is_ok());
        assert!(verify_pkey_ctx_copy_ecdsa(&e, NID_secp384r1, 48, 96).is_ok());
        assert!(verify_pkey_ctx_copy_ecdsa(&e, NID_secp521r1, 20, 132).is_ok());
        assert!(verify_pkey_ctx_copy_ecdsa(&e, NID_secp521r1, 32, 132).is_ok());
        assert!(verify_pkey_ctx_copy_ecdsa(&e, NID_secp521r1, 48, 132).is_ok());
        assert!(verify_pkey_ctx_copy_ecdsa(&e, NID_secp521r1, 64, 132).is_ok());
    }

    #[test]
    fn test_pkey_ctx_copy_ecdh() {
        let e = load_engine();
        assert!(verify_pkey_ctx_copy_ecdh(&e, NID_X9_62_prime256v1).is_ok());
        assert!(verify_pkey_ctx_copy_ecdh(&e, NID_secp384r1).is_ok());
        assert!(verify_pkey_ctx_copy_ecdh(&e, NID_secp521r1).is_ok());
    }

    // Helper functions
    fn verify_pkey_ctx_copy_ecdsa(
        e: &Engine,
        curve_name: u32,
        dgst_len: usize,
        sig_len: usize,
    ) -> OpenSSLResult<()> {
        let pkey_keygen_ctx = init_pkey_ctx(e, curve_name);
        let pkey = generate_test_key(&pkey_keygen_ctx, true, false);

        let pkey_ctx = create_ctx_from_pkey(e, &pkey);
        let result = ec_op_init(pkey_ctx.as_mut_ptr());
        assert!(result.is_ok());

        let dgst = vec![1u8; dgst_len];
        let sig = ec_sign_cb(pkey_ctx.as_mut_ptr(), &dgst)?;
        assert!(!sig.is_empty());
        assert_eq!(sig.len(), sig_len);
        assert!(sig != dgst);

        let pkey_ctx_copy_ptr = pkey_ctx.dup();
        assert!(pkey_ctx_copy_ptr.is_some());
        let pkey_ctx_copy: EvpPKeyCtx<EcKeyData> =
            EvpPKeyCtx::new_from_ptr(pkey_ctx_copy_ptr.unwrap());

        let result = ec_verify_cb(pkey_ctx_copy.as_mut_ptr(), &sig, &dgst);
        assert!(result.is_ok());

        Ok(())
    }

    fn verify_pkey_ctx_copy_ecdh(e: &Engine, curve_name: u32) -> OpenSSLResult<()> {
        let pkey_keygen_ctx1 = init_pkey_ctx(e, curve_name);
        let pkey1 = generate_test_key(&pkey_keygen_ctx1, true, true);

        let pkey_keygen_ctx2 = init_pkey_ctx(e, curve_name);
        let pkey2 = generate_test_key(&pkey_keygen_ctx2, true, true);

        let pkey_ctx1 = create_ctx_from_pkey(e, &pkey1);
        let pkey_ctx2 = create_ctx_from_pkey(e, &pkey2);

        let pkey_ctx1_copy_ptr = pkey_ctx1.dup();
        assert!(pkey_ctx1_copy_ptr.is_some());

        let pkey_ctx1_copy: EvpPKeyCtx<EcKeyData> =
            EvpPKeyCtx::new_from_ptr(pkey_ctx1_copy_ptr.unwrap());

        let pkey1_copy = pkey_ctx1_copy.get_evp_pkey().expect("Could not get pkey");

        // Derive with Key1_copy and pubkey2
        assert!(ec_op_init(pkey_ctx1_copy.as_mut_ptr()).is_ok());
        assert!(ec_ctrl_cb(
            pkey_ctx1_copy.as_mut_ptr(),
            EcCtrlOp::PeerKey(pkey2.as_mut_ptr())
        )
        .is_ok());

        let secret1_copy = ec_derive_cb(pkey_ctx1_copy.as_mut_ptr())
            .expect("Could not derive secret with key1_copy and pubkey2");

        // Derive with Key2 and pubkey_copy1
        assert!(ec_op_init(pkey_ctx2.as_mut_ptr()).is_ok());
        assert!(ec_ctrl_cb(
            pkey_ctx2.as_mut_ptr(),
            EcCtrlOp::PeerKey(pkey1_copy.as_mut_ptr())
        )
        .is_ok());

        let secret2_copy = ec_derive_cb(pkey_ctx2.as_mut_ptr())
            .expect("Could not derive secret with key2 and pubkey_copy1");

        assert_ne!(secret1_copy, secret2_copy);

        Ok(())
    }

    fn pkey_test_ecdsa(
        e: &Engine,
        curve_name: u32,
        dgst_len: usize,
        sig_len: usize,
    ) -> OpenSSLResult<()> {
        let pkey_keygen_ctx = init_pkey_ctx(e, curve_name);
        let pkey = generate_test_key(&pkey_keygen_ctx, true, false);

        let pkey_ctx = create_ctx_from_pkey(e, &pkey);
        ec_op_init(pkey_ctx.as_mut_ptr())?;

        let dgst = vec![1u8; dgst_len];
        let sig = ec_sign_cb(pkey_ctx.as_mut_ptr(), &dgst)?;
        assert!(!sig.is_empty());
        assert_eq!(sig.len(), sig_len);
        assert!(sig != dgst);

        ec_verify_cb(pkey_ctx.as_mut_ptr(), &sig, &dgst)?;
        Ok(())
    }

    fn pkey_test_ecdsa_ctx(
        e: &Engine,
        curve_name: u32,
        md_type: EvpMdType,
        sig_len: usize,
    ) -> OpenSSLResult<()> {
        let pkey_keygen_ctx = init_pkey_ctx(e, curve_name);
        let pkey = generate_test_key(&pkey_keygen_ctx, true, false);

        let pkey_ctx = create_ctx_from_pkey(e, &pkey);
        ec_op_init(pkey_ctx.as_mut_ptr())?;

        let md = EvpMd::new(md_type);
        let md_ctx = EvpMdCtx::new().unwrap();
        let tbs = vec![0xaau8; 64];
        md_ctx.digest_init(&md)?;
        md_ctx.digest_update(&tbs)?;
        ec_sign_verify_ctx_init_cb(pkey_ctx.as_mut_ptr(), md_ctx.as_mut_ptr())?;

        let sig_get_len = match ec_signctx_cb(pkey_ctx.as_mut_ptr(), md_ctx.as_mut_ptr(), true)? {
            SignCtxResult::SigLen(sig_len) => sig_len,
            _ => panic!("Did not get a signature length"),
        };
        assert_eq!(sig_len, sig_get_len);
        let sig = match ec_signctx_cb(pkey_ctx.as_mut_ptr(), md_ctx.as_mut_ptr(), false)? {
            SignCtxResult::Sig(sig) => {
                assert!(!sig.is_empty());
                assert_eq!(sig.len(), sig_len);
                assert!(sig != tbs);
                sig
            }
            _ => panic!("Did not get a signature result"),
        };

        md_ctx.digest_init(&md)?;
        md_ctx.digest_update(&tbs)?;
        ec_sign_verify_ctx_init_cb(pkey_ctx.as_mut_ptr(), md_ctx.as_mut_ptr())?;
        ec_verifyctx_cb(pkey_ctx.as_mut_ptr(), &sig, md_ctx.as_mut_ptr())?;
        Ok(())
    }

    fn verify_ecdh_compute_secret(e: &Engine, curve_name: u32) -> TestResult<()> {
        let pkey_keygen_ctx1 = init_pkey_ctx(e, curve_name);
        let pkey1 = generate_test_key(&pkey_keygen_ctx1, true, true);

        let pkey_keygen_ctx2 = init_pkey_ctx(e, curve_name);
        let pkey2 = generate_test_key(&pkey_keygen_ctx2, true, true);

        let pkey_ctx1 = create_ctx_from_pkey(e, &pkey1);
        let pkey_ctx2 = create_ctx_from_pkey(e, &pkey2);

        assert!(ec_op_init(pkey_ctx1.as_mut_ptr()).is_ok());

        assert!(ec_ctrl_cb(
            pkey_ctx1.as_mut_ptr(),
            EcCtrlOp::PeerKey(pkey2.as_mut_ptr())
        )
        .is_ok());

        assert!(ec_op_init(pkey_ctx2.as_mut_ptr()).is_ok());
        assert!(ec_ctrl_cb(
            pkey_ctx2.as_mut_ptr(),
            EcCtrlOp::PeerKey(pkey1.as_mut_ptr())
        )
        .is_ok());

        let secret1 = ec_derive_cb(pkey_ctx1.as_mut_ptr()).expect("Could not derive secret");
        let secret2 = ec_derive_cb(pkey_ctx2.as_mut_ptr()).expect("Could not derive secret");

        assert_ne!(secret1, secret2);

        cleanup_pkey_ctx(pkey_ctx1);
        cleanup_pkey_ctx(pkey_ctx2);
        Ok(())
    }

    fn verify_gen_no_curve(e: &Engine, keygen: bool) -> TestResult<()> {
        let pkey_ctx = create_ec_pkey_ctx(e);
        assert!(ec_paramgen_init_cb(pkey_ctx.as_mut_ptr()).is_ok());
        assert!(check_param_init(&pkey_ctx).is_ok());

        let pkey = EvpPKey::new().expect("Could not make pkey");
        if keygen {
            assert!(ec_keygen_cb(pkey_ctx.as_mut_ptr(), pkey.as_mut_ptr()).is_err());
        } else {
            assert!(ec_paramgen_cb(pkey_ctx.as_mut_ptr(), pkey.as_mut_ptr()).is_err());
        }

        cleanup_pkey_ctx(pkey_ctx);
        Ok(())
    }

    fn generate_test_key(pkey_ctx: &EvpPKeyCtx<EcKeyData>, keygen: bool, ecdh: bool) -> EvpPKey {
        let pkey = EvpPKey::new().expect("Could not make pkey");

        if keygen {
            assert!(ec_op_init(pkey_ctx.as_mut_ptr()).is_ok());
            if ecdh {
                ec_ctrl_cb(pkey_ctx.as_mut_ptr(), EcCtrlOp::KeyUsageEcdh)
                    .expect("Could not set key usage");
            }
            assert!(check_op_init(pkey_ctx, ecdh).is_ok());
            assert!(ec_keygen_cb(pkey_ctx.as_mut_ptr(), pkey.as_mut_ptr()).is_ok());
        } else {
            assert!(ec_paramgen_cb(pkey_ctx.as_mut_ptr(), pkey.as_mut_ptr()).is_ok());
        }

        if keygen {
            let ec_key_ptr = pkey.ec_key().expect("EC_KEY is null");
            let ec_key: EcKey<EcKeyData> = EcKey::new_from_ptr(ec_key_ptr);
            let pub_key = ec_key.get_pubkey_der().expect("Could not get pubkey");
            assert!(!pub_key.is_empty());
        }
        pkey
    }

    fn verify_gen(e: &Engine, curve_name: u32, keygen: bool, ecdh: bool) -> TestResult<EvpPKey> {
        let pkey_ctx = init_pkey_ctx(e, curve_name);
        let pkey = generate_test_key(&pkey_ctx, keygen, ecdh);
        let pkey_curve_name = get_curve_name(&pkey);
        assert_eq!(pkey_curve_name, curve_name as i32);
        cleanup_pkey_ctx(pkey_ctx);
        Ok(pkey)
    }

    fn keygen_from_param(ctx: &EvpPKeyCtx<EcKeyData>, ecdh: bool) -> EvpPKey {
        let pkey = EvpPKey::new().expect("Could not make pkey");
        assert!(ec_op_init(ctx.as_mut_ptr()).is_ok());
        if ecdh {
            ec_ctrl_cb(ctx.as_mut_ptr(), EcCtrlOp::KeyUsageEcdh).expect("Could not set key usage");
        }
        assert!(ec_keygen_cb(ctx.as_mut_ptr(), pkey.as_mut_ptr()).is_ok());

        pkey
    }

    fn verify_keygen_from_param(e: &Engine, param: EvpPKey, ecdh: bool) -> TestResult<()> {
        let param_curve_name = get_curve_name(&param);
        let pkey_ctx = create_ctx_from_pkey(e, &param);

        let pkey = keygen_from_param(&pkey_ctx, ecdh);
        let pkey_curve_name = get_curve_name(&pkey);
        assert_eq!(param_curve_name, pkey_curve_name);

        cleanup_pkey_ctx(pkey_ctx);
        Ok(())
    }

    fn get_curve_name(pkey: &EvpPKey) -> i32 {
        let ec_key_ptr = pkey.ec_key().expect("EC_KEY is null");
        let ec_key: EcKey<EcKeyData> = EcKey::new_from_ptr(ec_key_ptr);
        ec_key.curve_name().expect("Could not get curve name")
    }

    fn init_pkey_ctx(e: &Engine, curve_nid: u32) -> EvpPKeyCtx<EcKeyData> {
        let pkey_ctx = create_ec_pkey_ctx(e);
        assert!(ec_paramgen_init_cb(pkey_ctx.as_mut_ptr()).is_ok());
        assert!(check_param_init(&pkey_ctx).is_ok());

        ec_ctrl_cb(
            pkey_ctx.as_mut_ptr(),
            EcCtrlOp::ParamgenCurveNid(curve_nid as i32),
        )
        .expect("Could not set curve");

        pkey_ctx
    }

    fn create_ec_pkey_ctx(e: &Engine) -> EvpPKeyCtx<EcKeyData> {
        let key_type = EvpPKeyType::Ec;
        let pkey_ctx: EvpPKeyCtx<EcKeyData> =
            EvpPKeyCtx::new_from_id(key_type.nid(), e).expect("Could not make pkey ctx");
        pkey_ctx
    }

    fn create_ctx_from_pkey(e: &Engine, pkey: &EvpPKey) -> EvpPKeyCtx<EcKeyData> {
        let pkey_ctx: EvpPKeyCtx<EcKeyData> =
            EvpPKeyCtx::new(pkey, e).expect("Could not make pkey ctx");
        pkey_ctx
    }

    fn cleanup_pkey_ctx(pkey_ctx: EvpPKeyCtx<EcKeyData>) {
        ec_cleanup_cb(pkey_ctx.as_mut_ptr());
    }
}
