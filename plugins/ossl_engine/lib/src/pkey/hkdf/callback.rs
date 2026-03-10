// Copyright (C) Microsoft Corporation. All rights reserved.

use openssl_rust::safeapi::error::*;
use openssl_rust::safeapi::evp_pkey::callback::hkdf::*;
use openssl_rust::safeapi::evp_pkey::ctx::EvpPKeyCtx;
use openssl_rust::EVP_PKEY_CTX;

use crate::ciphers::init::AesType;
use crate::ciphers::key::AesKey;
use crate::common::base_key::Key;
use crate::common::base_key::ENGINE_KEY_HANDLE_TABLE;
use crate::get_or_create_keydata;
use crate::pkey::hkdf::key::*;

/// HKDF cleanup callback
/// This function is called whenever the PKey context is cleaned up for EVP_PKEY_HKDF algorithm.
///
/// # Arguments
/// * `ctx_ptr` - The EVP_PKEY_CTX context
pub fn hkdf_cleanup_cb(ctx_ptr: *mut EVP_PKEY_CTX) {
    let ctx: EvpPKeyCtx<HkdfData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    if let Some(hkdf_data) = ctx.get_data() {
        if let Some(secret_handle) = hkdf_data.secret_handle() {
            if ENGINE_KEY_HANDLE_TABLE
                .remove_secret_key(secret_handle)
                .is_err()
            {
                tracing::warn!(
                    "Failed to remove secret handle {} from the key handle table",
                    secret_handle
                );
            }
        }
        ctx.free_data();
    }
}

/// HKDF derive-init callback
/// This function is called before the key derivation operation for EVP_PKEY_HKDF algorithm.
/// The algorithm parameters will be set after this callback by the user.
///
/// # Arguments
/// * `ctx_ptr` - The EVP_PKEY_CTX context
///
/// # Returns
/// * `OpenSSLResult<()>` - The result of the derive-init operation
pub fn hkdf_derive_init_cb(ctx_ptr: *mut EVP_PKEY_CTX) -> OpenSSLResult<()> {
    let ctx: EvpPKeyCtx<HkdfData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    let hkdf_data = get_or_create_keydata!(ctx, HkdfData)?;
    hkdf_data.init();

    Ok(())
}

/// HKDF derive callback
/// This function is called when the key derivation operation is performed for EVP_PKEY_HKDF algorithm.
///
/// # Arguments
/// * `ctx_ptr` - The EVP_PKEY_CTX context
/// * `out_len` - The length of the derived key
///
/// # Returns
/// * `OpenSSLResult<HkdfDeriveResult>` - The result of the derive operation
pub fn hkdf_derive_cb(
    ctx_ptr: *mut EVP_PKEY_CTX,
    out_len: usize,
) -> OpenSSLResult<HkdfDeriveResult> {
    let ctx: EvpPKeyCtx<HkdfData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    let hkdf_data = ctx.get_data().ok_or(OpenSSLError::InvalidKeyData)?;

    // For all modes, input key is a secret key
    // extract -> not supported
    // expand -> not supported
    // extract and expand -> target is a aes key

    let secret_handle = hkdf_data
        .secret_handle()
        .ok_or(OpenSSLError::MissingKey("HKDF".to_string()))?;
    let secret_key = ENGINE_KEY_HANDLE_TABLE.get_secret_key(secret_handle)?;
    let input_secret_key = secret_key.hsm_key();

    if hkdf_data.mode() != EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND {
        Err(OpenSSLError::HkdfUnsupportedMode)?;
    }

    let (target_aes_key, aes_type) = hkdf_data.derive(input_secret_key, out_len)?;
    let aes_key = AesKey::from_derived_key(aes_type, target_aes_key)?;

    let handle = ENGINE_KEY_HANDLE_TABLE.insert_key(Key::Aes(aes_key));
    Ok(HkdfDeriveResult::Handle(handle))
}

/// HKDF control callback
/// This function is called when the control operation is performed for EVP_PKEY_HKDF algorithm.
///
/// # Arguments
/// * `ctx_ptr` - The EVP_PKEY_CTX context
/// * `op` - The control operation
///
/// # Returns
/// * `OpenSSLResult<()>` - The result of the control operation
pub fn hkdf_ctrl_cb(ctx_ptr: *mut EVP_PKEY_CTX, op: HkdfCtrlOp) -> OpenSSLResult<()> {
    let ctx: EvpPKeyCtx<HkdfData> = EvpPKeyCtx::new_from_ptr(ctx_ptr);
    let hkdf_data = ctx.get_data().ok_or(OpenSSLError::InvalidKeyData)?;

    match op {
        HkdfCtrlOp::SetSalt(salt) => hkdf_data.set_salt(salt)?,
        HkdfCtrlOp::AddInfo(info) => hkdf_data.add_info(info)?,
        HkdfCtrlOp::SetMd(md) => hkdf_data.set_md(md)?,
        HkdfCtrlOp::SetKey(secret_handle) => {
            let _ = ENGINE_KEY_HANDLE_TABLE.get_secret_key(secret_handle)?;
            hkdf_data.set_secret_handle(secret_handle);
        }
        HkdfCtrlOp::SetMode(mode) => hkdf_data.set_mode(mode)?,
        HkdfCtrlOp::SetKeyType(target_key_type) => {
            let aes_type = AesType::from_nid(target_key_type)?;
            hkdf_data.set_key_type(aes_type)?;
        }
        HkdfCtrlOp::SetKbkdf => hkdf_data.set_kbkdf()?,
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use openssl_rust::safeapi::evp_pkey::ctx::EvpPKeyCtx;
    use openssl_rust::safeapi::evp_pkey::method::EvpPKeyType;
    use openssl_rust::NID_aes_128_cbc;
    use openssl_rust::NID_aes_192_cbc;
    use openssl_rust::NID_aes_256_cbc;
    #[cfg(feature = "gcm")]
    use openssl_rust::NID_aes_256_gcm;
    #[cfg(feature = "xts")]
    use openssl_rust::NID_aes_256_xts;
    use openssl_rust::NID_sha1;
    use openssl_rust::NID_sha256;
    use openssl_rust::NID_sha384;
    use openssl_rust::NID_sha512;

    use super::*;
    use crate::load_engine;

    #[test]
    fn test_set_salt() {
        let evp_ctx = init_pkey_ctx();
        let ctx_ptr = evp_ctx.as_ptr() as *mut EVP_PKEY_CTX;
        let hkdf_data = evp_ctx.get_data().expect("Could not hkdf get data");

        assert!(!hkdf_data.is_kbkdf());
        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::SetSalt(vec![0x01, 0x02, 0x03])).is_ok());
        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::SetSalt(vec![1; 64])).is_ok());
        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::SetSalt(vec![1; 65])).is_err());

        cleanup_pkey_ctx(ctx_ptr);
    }

    #[test]
    fn test_set_label() {
        let evp_ctx = init_pkey_ctx();
        let ctx_ptr = evp_ctx.as_ptr() as *mut EVP_PKEY_CTX;
        let hkdf_data = evp_ctx.get_data().expect("Could not hkdf get data");

        assert!(!hkdf_data.is_kbkdf());
        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::SetKbkdf).is_ok());
        assert!(hkdf_data.is_kbkdf());
        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::SetSalt(vec![0x01, 0x02, 0x03])).is_ok());
        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::SetSalt(vec![1; 16])).is_ok());
        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::SetSalt(vec![1; 17])).is_err());

        cleanup_pkey_ctx(ctx_ptr);
    }

    #[test]
    fn test_set_md() {
        let evp_ctx = init_pkey_ctx();
        let ctx_ptr = evp_ctx.as_ptr() as *mut EVP_PKEY_CTX;
        let hkdf_data = evp_ctx.get_data().expect("Could not hkdf get data");

        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::SetMd(NID_sha256 as i32)).is_ok());
        assert!(hkdf_data.md() == Some(MdType::Sha256));

        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::SetMd(NID_sha384 as i32)).is_ok());
        assert!(hkdf_data.md() == Some(MdType::Sha384));

        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::SetMd(NID_sha512 as i32)).is_ok());
        assert!(hkdf_data.md() == Some(MdType::Sha512));

        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::SetMd(NID_sha1 as i32)).is_err());
        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::SetMd(0)).is_err());

        cleanup_pkey_ctx(ctx_ptr);
    }

    #[test]
    fn test_set_wrong_key() {
        let evp_ctx = init_pkey_ctx();
        let ctx_ptr = evp_ctx.as_ptr() as *mut EVP_PKEY_CTX;

        let secret_handle = 1;
        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::SetKey(secret_handle)).is_err());

        cleanup_pkey_ctx(ctx_ptr);
    }

    #[test]
    fn test_set_mode() {
        let evp_ctx = init_pkey_ctx();
        let ctx_ptr = evp_ctx.as_ptr() as *mut EVP_PKEY_CTX;
        let hkdf_data = evp_ctx.get_data().expect("Could not hkdf get data");

        assert!(hkdf_data.mode() == EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND);

        assert!(hkdf_ctrl_cb(
            ctx_ptr,
            HkdfCtrlOp::SetMode(EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)
        )
        .is_err());
        assert!(hkdf_data.mode() == EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND);

        assert!(hkdf_ctrl_cb(
            ctx_ptr,
            HkdfCtrlOp::SetMode(EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)
        )
        .is_err());
        assert!(hkdf_data.mode() == EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND);

        assert!(hkdf_ctrl_cb(
            ctx_ptr,
            HkdfCtrlOp::SetMode(EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)
        )
        .is_err());
        assert!(hkdf_data.mode() == EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND);

        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::SetMode(3)).is_err());
        assert!(hkdf_data.mode() == EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND);

        cleanup_pkey_ctx(ctx_ptr);
    }

    #[test]
    fn test_add_info_or_context() {
        let evp_ctx = init_pkey_ctx();
        let ctx_ptr = evp_ctx.as_ptr() as *mut EVP_PKEY_CTX;
        let hkdf_data = evp_ctx.get_data().expect("Could not hkdf get data");

        // case 1: 16 bytes
        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::AddInfo(vec![0x01; 16])).is_ok());

        // case 2: append up to 16
        assert!(hkdf_derive_init_cb(ctx_ptr).is_ok());
        let info1 = vec![0x01, 0x02, 0x03];
        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::AddInfo(info1.clone())).is_ok());
        let info2 = vec![0x8; 13];
        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::AddInfo(info2.clone())).is_ok());
        let mut total_info = vec![0; 16];
        total_info[..3].copy_from_slice(&info1);
        total_info[3..].copy_from_slice(&info2);
        let cur_info = hkdf_data.info().expect("Info is not set");
        assert!(cur_info.len() == 16);
        assert!(cur_info == total_info);

        // case 3: Exceed 16 bytes
        assert!(hkdf_derive_init_cb(ctx_ptr).is_ok());
        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::AddInfo(vec![0x01; 17])).is_err());

        // case 4: Append exceed 16 bytes
        assert!(hkdf_derive_init_cb(ctx_ptr).is_ok());
        let info1 = vec![0x01, 0x02, 0x03];
        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::AddInfo(info1)).is_ok());
        let info2 = vec![0x8; 14];
        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::AddInfo(info2)).is_err());

        cleanup_pkey_ctx(ctx_ptr);
    }

    #[test]
    fn test_set_key_type() {
        let evp_ctx = init_pkey_ctx();
        let ctx_ptr = evp_ctx.as_ptr() as *mut EVP_PKEY_CTX;
        let hkdf_data = evp_ctx.get_data().expect("Could not hkdf get data");

        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::SetKeyType(NID_aes_128_cbc as i32)).is_ok());
        assert!(hkdf_data.key_type() == Some(AesType::Aes128Cbc));

        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::SetKeyType(NID_aes_192_cbc as i32)).is_ok());
        assert!(hkdf_data.key_type() == Some(AesType::Aes192Cbc));

        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::SetKeyType(NID_aes_256_cbc as i32)).is_ok());
        assert!(hkdf_data.key_type() == Some(AesType::Aes256Cbc));

        #[cfg(feature = "gcm")]
        {
            assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::SetKeyType(NID_aes_256_gcm as i32)).is_ok());
            assert!(hkdf_data.key_type() == Some(AesType::Aes256Gcm));
        }

        #[cfg(feature = "xts")]
        {
            assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::SetKeyType(NID_aes_256_xts as i32)).is_err());
        }

        assert!(hkdf_ctrl_cb(ctx_ptr, HkdfCtrlOp::SetKeyType(0)).is_err());

        cleanup_pkey_ctx(ctx_ptr);
    }

    fn init_pkey_ctx() -> EvpPKeyCtx<HkdfData> {
        let e = load_engine();
        let key_type = EvpPKeyType::Hkdf;
        let pkey_ctx: EvpPKeyCtx<HkdfData> =
            EvpPKeyCtx::new_from_id(key_type.nid(), &e).expect("Could not make pkey ctx");
        let pkey_ctx_ptr = pkey_ctx.as_ptr() as *mut EVP_PKEY_CTX;
        assert!(hkdf_derive_init_cb(pkey_ctx_ptr).is_ok());
        pkey_ctx
    }

    fn cleanup_pkey_ctx(ctx_ptr: *mut EVP_PKEY_CTX) {
        hkdf_cleanup_cb(ctx_ptr);
    }
}
