// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_int;
use std::ffi::c_ushort;

use api_interface::REPORT_DATA_SIZE;
use mcr_api_resilient::*;
use openssl_rust::safeapi::error::*;
use openssl_rust::safeapi::evp_md::ctx::EvpMdCtx;
use openssl_rust::safeapi::evp_md::md::EvpMd;
use openssl_rust::safeapi::evp_md::md::EvpMdType;
use openssl_rust::safeapi::evp_pkey::callback::common::SignCtxResult;
use openssl_rust::safeapi::evp_pkey::callback::rsa::RsaCtrlOp;
use openssl_rust::safeapi::evp_pkey::callback::rsa::RsaCtrlOpResult;
use openssl_rust::safeapi::evp_pkey::ctx::EvpPKeyCtx;
use openssl_rust::safeapi::evp_pkey::pkey::EvpPKey;
use openssl_rust::safeapi::rsa::key::RsaKey;
use openssl_rust::EVP_MD_CTX;
use openssl_rust::EVP_MD_CTX_FLAG_FINALISE;
use openssl_rust::EVP_PKEY;
use openssl_rust::EVP_PKEY_CTX;
use openssl_rust::RSA_PKCS1_OAEP_PADDING;

use crate::common::hash::azihsm_hash_type;
use crate::common::hash::openssl_hash_nid;
use crate::common::hsm_key::HsmKeyContainer;
use crate::common::rsa_key::azihsm_sig_padding;
use crate::common::rsa_key::openssl_sig_padding;
use crate::common::rsa_key::RsaKeyData;
use crate::common::rsa_key::RsaKeyUsage;
use crate::rsa::callback::rsa_attest_key;

/// Import the RSA key from the wrapped key blob
///
/// # Arguments
/// * `ctx_ptr` - Pointer to `EVP_PKEY_CTX`
/// * `wrapped_blob` - Key blob to unwrap and import
/// * `digest_kind` - Digest used to wrap the blob
/// * `key_usage` - Usage of the imported key
/// * `key_availability` - Availability of the imported key
/// * `key_name` - Name of the imported key
/// * `is_crt` - Is the key in CRT format
///
/// # Return
/// `Ok(())` on success, or an `OpenSSLError`
pub fn pkey_rsa_import_key(
    ctx_ptr: *mut EVP_PKEY_CTX,
    wrapped_blob: &[u8],
    digest_kind: DigestKind,
    key_usage: KeyUsage,
    key_availability: KeyAvailability,
    key_name: Option<u16>,
    is_crt: bool,
) -> OpenSSLResult<()> {
    let rsa_key_usage = RsaKeyUsage::try_from(key_usage)?;

    let key_class = if is_crt {
        KeyClass::RsaCrt
    } else {
        KeyClass::Rsa
    };

    let key_container = HsmKeyContainer::unwrap_key(
        wrapped_blob.to_vec(),
        key_class,
        digest_kind,
        key_usage,
        key_availability,
        key_name,
    )?;

    let ctx: EvpPKeyCtx<RsaKeyData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);

    if let Some(mut cur_rsa_key) = ctx.rsa_from_pkey() {
        cur_rsa_key.free_data();
    }

    let pkey = ctx.get_evp_pkey()?;
    let mut rsa: RsaKey<RsaKeyData> = RsaKey::new()?;

    rsa.set_data(RsaKeyData::new())?;
    let rsa_keydata = rsa.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;
    rsa_keydata.set_imported_key(key_container);
    rsa_keydata.set_key_usage(rsa_key_usage);

    pkey.assign_rsa(rsa.as_mut_ptr())?;

    Ok(())
}

/// Open the given HSM private key by name
///
/// # Arguments
/// * `key_container` - Container of the opened key
///
/// # Returns
/// * `OpenSSLResult<EvpPKey>` - An `EvpPKey` with the key data
pub(crate) fn pkey_rsa_open_private_key(key_container: HsmKeyContainer) -> OpenSSLResult<EvpPKey> {
    let pub_key = key_container.export_public_key()?;

    let pkey = EvpPKey::new_unowned()?;
    let mut rsa: RsaKey<RsaKeyData> = RsaKey::from_der(pub_key)?;

    let rsa_keydata = RsaKeyData::new();
    rsa_keydata.set_imported_key(key_container);
    rsa_keydata.set_key_usage(RsaKeyUsage::Opened);

    rsa.set_data(rsa_keydata)?;
    pkey.assign_rsa(rsa.as_mut_ptr())?;

    Ok(pkey)
}

/// Attest an RSA key
///
/// # Arguments
/// * `pkey_ptr` - pointer to `EVP_PKEY` structure
/// * `report_data` - Report to the HSM
///
/// # Return
/// Attestation data, or error.
pub(crate) fn pkey_rsa_attest_key(
    pkey_ptr: *mut EVP_PKEY,
    report_data: &[u8; REPORT_DATA_SIZE as usize],
) -> OpenSSLResult<Vec<u8>> {
    let pkey = EvpPKey::new_from_ptr(pkey_ptr);
    rsa_attest_key(pkey.rsa()?, report_data)
}

/// Copy the RSA key data from source EVP_PKEY_CTX to destination EVP_PKEY_CTX
///
/// # Arguments
/// * `dst_ctx_ptr` - Destination EVP_PKEY_CTX
/// * `src_ctx_ptr` - Source EVP_PKEY_CTX
///
/// # Return
/// `Ok(())` on success, or an `OpenSSLError`
pub(crate) fn rsa_copy_cb(
    dst_ctx_ptr: *mut EVP_PKEY_CTX,
    src_ctx_ptr: *const EVP_PKEY_CTX,
) -> OpenSSLResult<()> {
    let src_ctx: EvpPKeyCtx<RsaKeyData> =
        EvpPKeyCtx::new_from_ptr(src_ctx_ptr as *mut EVP_PKEY_CTX);
    let src_rsa = src_ctx.rsa_from_pkey().ok_or(OpenSSLError::InvalidKey)?;
    let src_rsa_keydata = src_rsa.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;

    let dst_ctx: EvpPKeyCtx<RsaKeyData> = EvpPKeyCtx::new_from_ptr(dst_ctx_ptr);
    let mut dst_rsa = dst_ctx.rsa_from_pkey().ok_or(OpenSSLError::InvalidKey)?;

    // Copy the private key data from source to the destination
    let dst_rsa_keydata = src_rsa_keydata.clone();
    dst_rsa.reset_data()?;
    dst_rsa.set_data(dst_rsa_keydata)?;

    Ok(())
}

/// RSA encryption callback
/// This function is called whenever we encrypt with an RSA PKey.
///
/// # Arguments
/// * `ctx_ptr` - The `EVP_PKEY_CTX` context
/// * `input` - The data to encrypt
///
/// # Returns
/// * `OpenSSLResult<Vec<u8>>` - The result of the encryption operation.
pub fn rsa_encrypt_cb(ctx_ptr: *mut EVP_PKEY_CTX, input: &[u8]) -> OpenSSLResult<Vec<u8>> {
    let ctx = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    let rsa: RsaKey<RsaKeyData> = ctx.rsa_from_pkey().ok_or(OpenSSLError::InvalidKey)?;
    let rsa_keydata = rsa.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;
    rsa_keydata.encrypt(input)
}

/// RSA decryption callback
/// This function is called whenever we decrypt with an RSA PKey.
///
/// # Arguments
/// * `ctx_ptr` - The `EVP_PKEY_CTX` context
/// * `input` - The data to decrypt
///
/// # Returns
/// * `OpenSSLResult<Vec<u8>>` - The result of the decryption operation.
pub fn rsa_decrypt_cb(ctx_ptr: *mut EVP_PKEY_CTX, input: &[u8]) -> OpenSSLResult<Vec<u8>> {
    let ctx: EvpPKeyCtx<RsaKeyData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    let rsa: RsaKey<RsaKeyData> = ctx.rsa_from_pkey().ok_or(OpenSSLError::InvalidKey)?;
    let rsa_keydata = rsa.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;
    rsa_keydata.decrypt(input)
}

/// RSA signing/verifying ctx init callback
/// This function is called to start an RSA signing/verifying ctx operation.
///
/// # Arguments
/// * `_ctx_ptr` - The EVP_PKEY_CTX context
/// * `md_ctx_ptr` - The EVP_MD_CTX
///
/// # Returns
/// * `OpenSSLResult<()>` - The result of the init operation
#[allow(unused)]
pub fn rsa_sign_verify_ctx_init_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    md_ctx_ptr: *mut EVP_MD_CTX,
) -> OpenSSLResult<()> {
    let md_ctx = EvpMdCtx::new_from_ptr(md_ctx_ptr);
    md_ctx.set_flag(EVP_MD_CTX_FLAG_FINALISE as c_int);

    Ok(())
}

/// RSA signing callback
/// This function is called whenever we sign with an RSA PKey.
///
/// # Arguments
/// * `ctx_ptr` - The `EVP_PKEY_CTX` context
/// * `dgst` - The digest to sign
///
/// # Returns
/// * `OpenSSLResult<Vec<u8>>` - The result of the signing operation.
pub fn rsa_sign_cb(ctx_ptr: *mut EVP_PKEY_CTX, dgst: &[u8]) -> OpenSSLResult<Vec<u8>> {
    let ctx: EvpPKeyCtx<RsaKeyData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    let rsa: RsaKey<RsaKeyData> = ctx.rsa_from_pkey().ok_or(OpenSSLError::InvalidKey)?;
    let rsa_keydata = rsa.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;
    rsa_keydata.sign(dgst)
}

/// RSA signctx callback
/// This function is called when we do a signctx operation
///
/// # Arguments
/// * `ctx_ptr` - The `EVP_PKEY_CTX` context
/// * `md_ctx` - The `EVP_MD_CTX` context
/// * `get_siglen` - Whether or not to return the signature length
///
/// # Returns
/// The result of the signing operation
pub fn rsa_signctx_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    md_ctx: *mut EVP_MD_CTX,
    get_siglen: bool,
) -> OpenSSLResult<SignCtxResult> {
    let ctx: EvpPKeyCtx<RsaKeyData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    let rsa: RsaKey<RsaKeyData> = ctx.rsa_from_pkey().ok_or(OpenSSLError::InvalidKey)?;
    let rsa_keydata = rsa.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;

    if get_siglen {
        let sig_len = rsa_keydata.sig_len()?;
        Ok(SignCtxResult::SigLen(sig_len))
    } else {
        let md = EvpMdCtx::new_from_ptr(md_ctx);
        let hash_type = match md.get_md_type()? {
            EvpMdType::Sha1 => DigestKind::Sha1,
            EvpMdType::Sha256 => DigestKind::Sha256,
            EvpMdType::Sha384 => DigestKind::Sha384,
            EvpMdType::Sha512 => DigestKind::Sha512,
        };

        let digest = md.digest_final()?;

        let hash_type_old = rsa_keydata.get_hash_type();
        rsa_keydata.set_hash_type(Some(hash_type));
        let sig = match rsa_sign_cb(ctx_ptr, digest.as_slice()) {
            Ok(sig) => sig,
            Err(e) => {
                rsa_keydata.set_hash_type(hash_type_old);
                return Err(e);
            }
        };

        rsa_keydata.set_hash_type(hash_type_old);
        Ok(SignCtxResult::Sig(sig))
    }
}

/// RSA verification callback
/// This function is called whenever we verify with an RSA PKey.
///
/// # Arguments
/// * `ctx_ptr` - The `EVP_PKEY_CTX` context
/// * `sig` - The signature
/// * `dgst` - The digest to verify
///
/// # Returns
/// * `OpenSSLResult<()>` - The result of the verification operation.
pub fn rsa_verify_cb(ctx_ptr: *mut EVP_PKEY_CTX, sig: &[u8], dgst: &[u8]) -> OpenSSLResult<()> {
    let ctx: EvpPKeyCtx<RsaKeyData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    let rsa: RsaKey<RsaKeyData> = ctx.rsa_from_pkey().ok_or(OpenSSLError::InvalidKey)?;
    let rsa_keydata = rsa.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;
    rsa_keydata.verify(dgst, sig)
}

/// RSA verifyctx callback
/// This function is called when we do a verifyctx operation
///
/// # Arguments
/// * `ctx_ptr` - The `EVP_PKEY_CTX` context
/// * `sig` - The signature to verify
/// * `md_ctx` - The `EVP_MD_CTX` context
///
/// # Returns
/// The result of the signing operation
pub fn rsa_verifyctx_cb(
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

    let ctx: EvpPKeyCtx<RsaKeyData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    let rsa: RsaKey<RsaKeyData> = ctx.rsa_from_pkey().ok_or(OpenSSLError::InvalidKey)?;
    let rsa_keydata = rsa.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;

    let digest = md.digest_final()?;

    let hash_type_old = rsa_keydata.get_hash_type();
    rsa_keydata.set_hash_type(Some(hash_type));
    let result = rsa_verify_cb(ctx_ptr, sig, digest.as_slice());
    rsa_keydata.set_hash_type(hash_type_old);
    result
}

/// Stub function as RSA keygen/paramgen is not implemented
pub fn rsa_gen_init_cb(_: *mut EVP_PKEY_CTX) -> OpenSSLResult<()> {
    Err(OpenSSLError::NotImplemented)
}

/// Stub function
pub fn rsa_sign_verify_init_cb(_: *mut EVP_PKEY_CTX) -> OpenSSLResult<()> {
    Ok(())
}

/// Stub function
pub fn rsa_encrypt_decrypt_init_cb(_: *mut EVP_PKEY_CTX) -> OpenSSLResult<()> {
    Ok(())
}

/// Stub function as RSA keygen/paramgen is not implemented
pub fn rsa_gen_cb(_: *mut EVP_PKEY_CTX, _: *mut EVP_PKEY) -> OpenSSLResult<()> {
    Err(OpenSSLError::NotImplemented)
}

/// RSA ctrl callback
///
/// # Arguments
/// * `ctx_ptr` - A pointer to the EVP_PKEY_CTX object.
/// * `op` - The operation to be performed.
///
/// # Returns
/// Result of the operation.
pub(crate) fn rsa_ctrl_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    op: RsaCtrlOp,
) -> OpenSSLResult<Option<RsaCtrlOpResult>> {
    let ctx: EvpPKeyCtx<RsaKeyData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    let rsa: RsaKey<RsaKeyData> = ctx.rsa_from_pkey().ok_or(OpenSSLError::InvalidKey)?;
    let rsa_keydata = rsa.get_data()?.ok_or(OpenSSLError::InvalidKeyData)?;
    match op {
        // TODO: get/set salt length support needs to be added
        RsaCtrlOp::SetMd(nid) => {
            rsa_keydata.set_hash_type(azihsm_hash_type(nid)?);
            Ok(None)
        }
        RsaCtrlOp::SetOaepMd(nid) => {
            rsa_keydata.set_hash_type(azihsm_hash_type(nid)?);
            Ok(None)
        }
        RsaCtrlOp::SetPadding(id) => {
            rsa_keydata
                .set_sig_padding(azihsm_sig_padding(id)?.ok_or(OpenSSLError::PaddingNotSupported)?);
            Ok(None)
        }
        RsaCtrlOp::SetPssSaltLen(len) => {
            match len {
                -1 | -2 => {
                    // OSSL input -1 : digest size, -2 : auto-recovered from signature (set to digest size)
                    let md_type_nid = openssl_hash_nid(rsa_keydata.get_hash_type());
                    let salt_len = EvpMd::md_size(md_type_nid)?;
                    rsa_keydata.set_sig_salt_len(Some(salt_len as u16));
                }
                sl if sl >= 0 => {
                    rsa_keydata.set_sig_salt_len(Some(sl as u16));
                }
                _ => return Err(OpenSSLError::SaltLengthNotSupported),
            }
            Ok(None)
        }
        RsaCtrlOp::GetMd => Ok(Some(RsaCtrlOpResult::GetMd(openssl_hash_nid(
            rsa_keydata.get_hash_type(),
        )))),
        RsaCtrlOp::GetOaepMd => Ok(Some(RsaCtrlOpResult::GetOaepMd(openssl_hash_nid(
            rsa_keydata.get_hash_type(),
        )))),
        RsaCtrlOp::GetPadding => {
            let padding = match rsa_keydata.get_key_usage() {
                None | Some(RsaKeyUsage::EncryptDecrypt) => RSA_PKCS1_OAEP_PADDING,
                Some(RsaKeyUsage::SignVerify) => openssl_sig_padding(rsa_keydata.get_sig_padding()),
                Some(_) => Err(OpenSSLError::PaddingNotSupported)?,
            };
            Ok(Some(RsaCtrlOpResult::GetPadding(padding)))
        }
        RsaCtrlOp::GetPssSaltLen => match rsa_keydata.get_sig_salt_len() {
            Some(len) => Ok(Some(RsaCtrlOpResult::GetPssSaltLen(len as c_ushort))),
            None => Ok(Some(RsaCtrlOpResult::GetPssSaltLen(0))),
        },
        RsaCtrlOp::DigestInit => Ok(None), // Default is okay
    }
}
