// Copyright (C) Microsoft Corporation. All rights reserved.

use engine_common::handle_table::Handle;
use mcr_api_resilient::DigestKind;
use mcr_api_resilient::KeyAvailability;
use mcr_api_resilient::KeyUsage;
use openssl_rust::safeapi::error::*;
use openssl_rust::safeapi::evp_cipher::callback::*;
use openssl_rust::safeapi::evp_cipher::ctx::EvpCipherCtx;

use crate::ciphers::init::*;
use crate::ciphers::key::*;
use crate::common::base_key::Key;
use crate::common::base_key::ENGINE_KEY_HANDLE_TABLE;
use crate::common::hsm_key::HsmKeyContainer;

/// Unwrap the AES key from the wrapped blob and import it into the cipher context
///
/// # Arguments
/// * `ctx` - The cipher context
/// * `wrapped_blob` - The wrapped blob containing the key
/// * `wrapped_blob2` - The wrapped blob containing the second key for AES-256-XTS
/// * `key_usage` - The key usage
/// * `digest_kind` - The digest kind
///
/// # Returns
/// * `OpenSSLResult<()>` - The result of the import operation into the cipher context
pub(crate) fn aes_import_key(
    ctx: EvpCipherCtx,
    wrapped_blob: &[u8],
    wrapped_blob2: Option<&[u8]>,
    digest_kind: DigestKind,
    key_usage: KeyUsage,
    key_availability: KeyAvailability,
    key_name: Option<u16>,
) -> OpenSSLResult<()> {
    let aes_type = AesType::from_nid(ctx.nid())?;

    // Avoid unused variable warning for wrapped_blob2 if xts is not enabled
    #[cfg(not(feature = "xts"))]
    let _ = &wrapped_blob2;

    let key_class = aes_type.hsm_key_class();
    let key_container1 = HsmKeyContainer::unwrap_key(
        wrapped_blob.to_vec(),
        key_class,
        digest_kind,
        key_usage,
        key_availability,
        key_name,
    )?;

    // Only create key_container2 for AES-256-XTS
    #[cfg(feature = "xts")]
    let key_container2 = if matches!(aes_type, AesType::Aes256Xts) {
        let wrapped_blob2 = wrapped_blob2.ok_or(OpenSSLError::InvalidKeyData)?;
        Some(HsmKeyContainer::unwrap_key(
            wrapped_blob2.to_vec(),
            key_class,
            digest_kind,
            key_usage,
            key_availability,
            key_name,
        )?)
    } else {
        None
    };
    #[cfg(not(feature = "xts"))]
    let key_container2 = None;

    let aes_key_ctx = AesKey::from_imported_key(aes_type, key_container1, key_container2)?;
    let handle = ENGINE_KEY_HANDLE_TABLE.insert_key(Key::Aes(aes_key_ctx));
    ctx.set_cipher_data(handle)
}

/// AES-CBC init callback
/// This function is called whenever the cipher context is initialized with a key.
///
/// # Arguments
/// * `ctx` - The cipher context
/// * `key_handle` - User handle to the hsm key handle
/// * `iv` - The initialization vector
///
/// # Returns
/// * `OpenSSLResult<()>` - The result of the init operation
pub fn aes_init_cb(
    ctx: &EvpCipherCtx,
    key_handle: Option<Handle>,
    iv: Option<Vec<u8>>,
) -> OpenSSLResult<()> {
    let cur_handle = ctx.get_cipher_data()?;
    let handle = key_handle.unwrap_or(0);

    match (cur_handle, handle) {
        (0, 0) => {
            //ctx init with no key for the first time
            // Create a new key context. Do not generate key yet.
            aes_key_ctx_create(ctx, false, iv)?;
        }
        (_, 0) => {
            let mut cur_key_ctx = ENGINE_KEY_HANDLE_TABLE.get_aes_key(cur_handle)?;
            cur_key_ctx.set_iv(iv)?;
        }
        (_, _) => {
            if cur_handle == handle {
                let mut cur_key_ctx = ENGINE_KEY_HANDLE_TABLE.get_aes_key(cur_handle)?;
                // User wants to set the same key that was generated for this ctx earlier
                cur_key_ctx.set_iv(iv)?;
            } else {
                // drop old key handle and replace it with new key handle
                let mut key_ctx = ENGINE_KEY_HANDLE_TABLE.get_aes_key(handle)?;
                key_ctx.set_iv(iv)?;
                if cur_handle != 0 {
                    aes_cleanup_cb(ctx)?;
                }
                ctx.set_cipher_data(handle)?;
            }
        }
    }
    Ok(())
}

/// AES ctrl callback
/// This will be invoked from the EVP_CIPHER_CTX_ctrl function to perform
/// control operations on the cipher context.
/// This method allows user to get/set cipher specific parameters for a given cipher context.
///
/// # Arguments
/// * `ctx` - The cipher context
/// * `ctrl_op` - The control operation to perform
///
/// # Returns
/// * `CipherCtrlResult` - The result of the control operation
pub fn aes_ctrl_cb(ctx: &EvpCipherCtx, ctrl_op: CipherCtrlOp) -> OpenSSLResult<CipherCtrlResult> {
    match ctrl_op {
        CipherCtrlOp::RandKey => aes_ctrl_keygen(ctx),
        CipherCtrlOp::CtxCopy(out_ctx) => aes_ctrl_copy(ctx, out_ctx),
        CipherCtrlOp::CtrlInit => aes_ctrl_init(ctx),
        _ => {
            let key_handle = ctx.get_cipher_data()?;
            let mut aes_key_ctx = ENGINE_KEY_HANDLE_TABLE.get_aes_key(key_handle)?;
            aes_key_ctx.ctrl(ctrl_op)
        }
    }
}

/// AES cleanup callback
/// This function is called whenever the cipher context is
/// reinitalized with a different cipher method as well as when the ctx is freed.
/// We need to delete the hsm key handle if it is set in the cipher data.
///
/// # Arguments
/// * `ctx` - The cipher context
///
/// # Returns
/// * `OpenSSLResult<()>` - The result of the cleanup operation
pub fn aes_cleanup_cb(ctx: &EvpCipherCtx) -> OpenSSLResult<()> {
    let key_handle = ctx.get_cipher_data()?;
    ctx.set_cipher_data(0)?;
    // Dropping the key handle will delete the HsmKeyHandle too
    // if this is the last reference.
    // This should not be fatal, as that would cause a stale ctx
    // to remain around, but this is technically an error, so just log it.
    if ENGINE_KEY_HANDLE_TABLE.remove_aes_key(key_handle).is_err() {
        tracing::warn!("Attempted to remove nonexistent key handle: {key_handle}");
    }
    Ok(())
}

/// AES-CBC do_cipher callback for encryption/decryption
///
/// # Arguments
/// * `ctx` - The cipher context
/// * `in_data` - The input buffer
///
/// # Returns
/// * `OpenSSLResult<Vec<u8>>` - The output buffer is returned on success or an error
pub fn aes_cbc_do_cipher_cb(ctx: &EvpCipherCtx, in_data: Vec<u8>) -> OpenSSLResult<Vec<u8>> {
    let key_handle = ctx.get_cipher_data()?;
    let enc = ctx.is_encrypting();

    let mut aes_ctx = ENGINE_KEY_HANDLE_TABLE.get_aes_key(key_handle)?;

    aes_ctx.cbc_do_cipher(in_data, enc)
}

/// AES-GCM do_cipher callback for encryption/decryption
///
/// # Arguments
/// * `ctx` - The cipher context
/// * `in_data` - The input buffer
/// * `aad` - Flag to indicate if the input data is AAD
///
/// # Returns
/// * `OpenSSLResult<Option<Vec<u8>>>` - The output buffer is returned on success or an error
/// * If the input data is AAD, the output buffer is None
#[cfg(feature = "gcm")]
pub fn aes_gcm_do_cipher_cb(
    ctx: &EvpCipherCtx,
    in_data: Vec<u8>,
    aad: bool,
) -> OpenSSLResult<Option<Vec<u8>>> {
    let key_handle = ctx.get_cipher_data()?;
    let enc = ctx.is_encrypting();

    let mut aes_ctx = ENGINE_KEY_HANDLE_TABLE.get_aes_key(key_handle)?;

    aes_ctx.gcm_do_cipher(in_data, aad, enc)
}

/// AES-XTS do_cipher callback for encryption/decryption
///
/// # Arguments
/// * `ctx` - The cipher context
/// * `in_data` - The input buffer
///
/// # Returns
/// * `OpenSSLResult<Vec<u8>>` - The output buffer is returned on success or an error
#[cfg(feature = "xts")]
pub fn aes_xts_do_cipher_cb(ctx: &EvpCipherCtx, in_data: Vec<u8>) -> OpenSSLResult<Vec<u8>> {
    let key_handle = ctx.get_cipher_data()?;
    let enc = ctx.is_encrypting();

    let mut aes_ctx = ENGINE_KEY_HANDLE_TABLE.get_aes_key(key_handle)?;

    aes_ctx.xts_do_cipher(in_data, enc)
}

// Helper functions
fn aes_ctrl_init(ctx: &EvpCipherCtx) -> OpenSSLResult<CipherCtrlResult> {
    let key_handle = ctx.get_cipher_data()?;
    if key_handle != 0 {
        let mut key_ctx = ENGINE_KEY_HANDLE_TABLE.get_aes_key(key_handle)?;
        key_ctx.ctrl(CipherCtrlOp::CtrlInit)?;
    } else {
        aes_key_ctx_create(ctx, false, None)?;
    }
    Ok(CipherCtrlResult::CtrlInitSuccess)
}

fn aes_key_ctx_create(ctx: &EvpCipherCtx, keygen: bool, iv: Option<Vec<u8>>) -> OpenSSLResult<()> {
    let aes_type = AesType::from_nid(ctx.nid())?;

    let mut aes_key_ctx = AesKey::new(aes_type);
    if keygen {
        aes_key_ctx.generate_key()?;
    }
    aes_key_ctx.set_iv(iv)?;

    let handle = ENGINE_KEY_HANDLE_TABLE.insert_key(Key::Aes(aes_key_ctx));
    ctx.set_cipher_data(handle)?;

    Ok(())
}

fn aes_ctrl_keygen(ctx: &EvpCipherCtx) -> OpenSSLResult<CipherCtrlResult> {
    let key_handle = ctx.get_cipher_data()?;
    let mut key_ctx = ENGINE_KEY_HANDLE_TABLE.get_aes_key(key_handle)?;
    let handle = if key_ctx.is_initialized() {
        let iv = key_ctx.get_iv();
        aes_cleanup_cb(ctx)?;
        aes_key_ctx_create(ctx, true, Some(iv))?;
        ctx.get_cipher_data()?
    } else {
        key_ctx.generate_key()?;
        key_handle
    };
    Ok(CipherCtrlResult::KeyHandle(handle))
}

fn aes_ctrl_copy(ctx: &EvpCipherCtx, out_ctx: &EvpCipherCtx) -> OpenSSLResult<CipherCtrlResult> {
    let src_handle = ctx.get_cipher_data()?;
    let mut src_key_ctx = ENGINE_KEY_HANDLE_TABLE.get_aes_key(src_handle)?;

    aes_key_ctx_create(out_ctx, false, None)?;

    let mut dst_key_ctx = ENGINE_KEY_HANDLE_TABLE.get_aes_key(out_ctx.get_cipher_data()?)?;
    src_key_ctx.ctrl_copy(&mut dst_key_ctx)?;

    Ok(CipherCtrlResult::CopySuccess)
}

#[cfg(test)]
mod test {
    use openssl_rust::safeapi::callback::EngineCiphersResult;
    use openssl_rust::safeapi::engine::Engine;
    use openssl_rust::safeapi::evp_cipher::method::*;
    use rand::prelude::*;

    use super::*;
    use crate::load_engine;

    type TestResult<T> = Result<T, &'static str>;

    #[test]
    fn test_cipher_ctx_init() {
        assert!(validate_ctx_init(AesType::Aes128Cbc).is_ok());
        assert!(validate_ctx_init(AesType::Aes192Cbc).is_ok());
        assert!(validate_ctx_init(AesType::Aes256Cbc).is_ok());
        #[cfg(feature = "gcm")]
        assert!(validate_ctx_init(AesType::Aes256Gcm).is_ok());
        #[cfg(feature = "xts")]
        assert!(validate_ctx_init(AesType::Aes256Xts).is_ok());
    }

    #[test]
    fn test_cipher_ctx_init_with_iv() {
        assert!(validate_ctx_init_with_iv(AesType::Aes128Cbc).is_ok());
        assert!(validate_ctx_init_with_iv(AesType::Aes192Cbc).is_ok());
        assert!(validate_ctx_init_with_iv(AesType::Aes256Cbc).is_ok());
        #[cfg(feature = "gcm")]
        assert!(validate_ctx_init_with_iv(AesType::Aes256Gcm).is_ok());
        #[cfg(feature = "xts")]
        assert!(validate_ctx_init_with_iv(AesType::Aes256Xts).is_ok());
    }

    #[test]
    fn test_cipher_ctx_keygen_multi() {
        assert!(validate_ctx_keygen_multi(AesType::Aes128Cbc).is_ok());
        assert!(validate_ctx_keygen_multi(AesType::Aes192Cbc).is_ok());
        assert!(validate_ctx_keygen_multi(AesType::Aes256Cbc).is_ok());
        #[cfg(feature = "gcm")]
        assert!(validate_ctx_keygen_multi(AesType::Aes256Gcm).is_ok());
        #[cfg(feature = "xts")]
        assert!(validate_ctx_keygen_multi(AesType::Aes256Xts).is_ok());
    }

    #[test]
    fn test_cipher_ctx_keygen_init() {
        assert!(validate_ctx_keygen_init(AesType::Aes128Cbc).is_ok());
        assert!(validate_ctx_keygen_init(AesType::Aes192Cbc).is_ok());
        assert!(validate_ctx_keygen_init(AesType::Aes256Cbc).is_ok());
        #[cfg(feature = "gcm")]
        assert!(validate_ctx_keygen_init(AesType::Aes256Gcm).is_ok());
        #[cfg(feature = "xts")]
        assert!(validate_ctx_keygen_init(AesType::Aes256Xts).is_ok());
    }

    #[test]
    fn test_cipher_ctx_keygen_init_multi() {
        assert!(validate_ctx_keygen_init_multi(AesType::Aes128Cbc).is_ok());
        assert!(validate_ctx_keygen_init_multi(AesType::Aes192Cbc).is_ok());
        assert!(validate_ctx_keygen_init_multi(AesType::Aes256Cbc).is_ok());
        #[cfg(feature = "gcm")]
        assert!(validate_ctx_keygen_init_multi(AesType::Aes256Gcm).is_ok());
        #[cfg(feature = "xts")]
        assert!(validate_ctx_keygen_init_multi(AesType::Aes256Xts).is_ok());
    }

    #[test]
    fn test_cipher_ctx_keygen_init_deleted_key() {
        assert!(validate_ctx_keygen_init_deleted_key(AesType::Aes128Cbc).is_ok());
        assert!(validate_ctx_keygen_init_deleted_key(AesType::Aes192Cbc).is_ok());
        assert!(validate_ctx_keygen_init_deleted_key(AesType::Aes256Cbc).is_ok());
        #[cfg(feature = "gcm")]
        assert!(validate_ctx_keygen_init_deleted_key(AesType::Aes256Gcm).is_ok());
        #[cfg(feature = "xts")]
        assert!(validate_ctx_keygen_init_deleted_key(AesType::Aes256Xts).is_ok());
    }

    #[test]
    fn test_cipher_ctx_copy() {
        assert!(validate_ctx_copy(AesType::Aes128Cbc).is_ok());
        assert!(validate_ctx_copy(AesType::Aes192Cbc).is_ok());
        assert!(validate_ctx_copy(AesType::Aes256Cbc).is_ok());
        #[cfg(feature = "gcm")]
        assert!(validate_ctx_copy(AesType::Aes256Gcm).is_ok());
        #[cfg(feature = "xts")]
        assert!(validate_ctx_copy(AesType::Aes256Xts).is_ok());
    }

    #[test]
    fn test_cipher_ctx_aes_cbc_cipher() {
        assert!(validate_ctx_aes_cbc_cipher(AesType::Aes128Cbc).is_ok());
        assert!(validate_ctx_aes_cbc_cipher(AesType::Aes192Cbc).is_ok());
        assert!(validate_ctx_aes_cbc_cipher(AesType::Aes256Cbc).is_ok());
    }

    #[test]
    fn test_cipher_ctx_aes_cbc_cipher_multiblock() {
        assert!(validate_ctx_aes_cbc_cipher_multiblock(AesType::Aes128Cbc).is_ok());
        assert!(validate_ctx_aes_cbc_cipher_multiblock(AesType::Aes192Cbc).is_ok());
        assert!(validate_ctx_aes_cbc_cipher_multiblock(AesType::Aes256Cbc).is_ok());
    }

    #[test]
    fn test_cipher_ctx_aes_cbc_cipher_corruput_data() {
        assert!(validate_ctx_aes_cbc_cipher_corrupt_data(AesType::Aes128Cbc).is_ok());
        assert!(validate_ctx_aes_cbc_cipher_corrupt_data(AesType::Aes192Cbc).is_ok());
        assert!(validate_ctx_aes_cbc_cipher_corrupt_data(AesType::Aes256Cbc).is_ok());
    }

    #[test]
    fn test_cipher_ctx_aes_cbc_cipher_unaligned_data() {
        assert!(validate_ctx_aes_cbc_cipher_unaligned_data(AesType::Aes128Cbc).is_ok());
        assert!(validate_ctx_aes_cbc_cipher_unaligned_data(AesType::Aes192Cbc).is_ok());
        assert!(validate_ctx_aes_cbc_cipher_unaligned_data(AesType::Aes256Cbc).is_ok());
    }

    #[test]
    fn test_cipher_ctx_aes_cbc_cipher_invalid_datasize() {
        assert!(validate_ctx_aes_cbc_cipher_invalid_datasize(AesType::Aes128Cbc).is_ok());
        assert!(validate_ctx_aes_cbc_cipher_invalid_datasize(AesType::Aes192Cbc).is_ok());
        assert!(validate_ctx_aes_cbc_cipher_invalid_datasize(AesType::Aes256Cbc).is_ok());
    }

    #[test]
    fn test_cipher_ctx_aes_cbc_cipher_invalid_key() {
        assert!(validate_ctx_aes_cbc_cipher_invalid_key(AesType::Aes128Cbc).is_ok());
        assert!(validate_ctx_aes_cbc_cipher_invalid_key(AesType::Aes192Cbc).is_ok());
        assert!(validate_ctx_aes_cbc_cipher_invalid_key(AesType::Aes256Cbc).is_ok());
    }

    #[cfg(feature = "gcm")]
    #[test]
    fn test_cipher_ctx_aes_gcm_cipher_no_aad() {
        assert!(validate_ctx_aes_gcm_cipher(false).is_ok());
    }

    #[cfg(feature = "gcm")]
    #[test]
    fn test_cipher_ctx_aes_gcm_cipher_with_aad() {
        assert!(validate_ctx_aes_gcm_cipher(true).is_ok());
    }

    #[cfg(feature = "gcm")]
    #[test]
    fn test_cipher_ctx_aes_gcm_ctrl() {
        let engine = load_engine();
        let cipher = get_cipher(&engine, AesType::Aes256Gcm.nid());
        let cipher_ctx = create_ctx_with_rand_key(cipher, &engine, None, 1, true);

        // Ctrl init
        let result = aes_ctrl_cb(&cipher_ctx, CipherCtrlOp::CtrlInit);
        assert!(result.is_ok());

        // Set/Get IV len
        let result = aes_ctrl_cb(&cipher_ctx, CipherCtrlOp::SetIvLen(AES_GCM_IV_LEN as i32));
        assert!(result.is_ok());

        let wrong_iv_len = (AES_GCM_IV_LEN - 1) as i32;
        let result = aes_ctrl_cb(&cipher_ctx, CipherCtrlOp::SetIvLen(wrong_iv_len));
        assert!(result.is_err(), "result {:?}", result);

        let result = aes_ctrl_cb(&cipher_ctx, CipherCtrlOp::GetIvLen);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            CipherCtrlResult::IvLen(AES_GCM_IV_LEN as i32)
        );

        // Set/Get Tag
        let tag = vec![0x2; 16];
        let result = aes_ctrl_cb(&cipher_ctx, CipherCtrlOp::SetTag(Some(tag.clone()), 16));
        assert!(result.is_ok());

        let result = aes_ctrl_cb(&cipher_ctx, CipherCtrlOp::GetTag);
        let tag_result = match result {
            Ok(CipherCtrlResult::Tag(tag)) => tag,
            _ => {
                panic!("Could not get tag");
            }
        };
        assert_eq!(tag, tag_result);

        let result = aes_ctrl_cb(&cipher_ctx, CipherCtrlOp::SetTag(None, 16));
        assert!(result.is_ok());

        let result = aes_ctrl_cb(&cipher_ctx, CipherCtrlOp::GetTag);
        let tag_result = match result {
            Ok(CipherCtrlResult::Tag(tag)) => tag,
            _ => {
                panic!("Could not get tag");
            }
        };
        assert_eq!(tag_result, vec![0; 16]);

        let result = aes_ctrl_cb(&cipher_ctx, CipherCtrlOp::SetTag(None, 15));
        assert!(result.is_err(), "result {:?}", result);
    }

    #[cfg(feature = "xts")]
    #[test]
    fn test_cipher_ctx_aes_xts_cipher() {
        assert!(validate_ctx_aes_xts_cipher().is_ok());
    }

    // Helper functions to test the AES cipher context

    fn get_cipher(e: &Engine, nid: i32) -> &EvpCipherMethod {
        let result = engine_ciphers(e, nid);
        assert!(result.is_ok());
        match result {
            Ok(EngineCiphersResult::Cipher(cipher)) => cipher,
            _ => {
                panic!("Could not get engine ciphers");
            }
        }
    }

    fn validate_ctx_init(aes_type: AesType) -> TestResult<()> {
        let engine = load_engine();
        let cipher = get_cipher(&engine, aes_type.nid());
        let cipher_ctx: EvpCipherCtx = EvpCipherCtx::new().expect("Could not make cipher ctx");

        let result = cipher_ctx.init(cipher, &engine, None, None, 1);
        assert!(result.is_ok());
        let handle = cipher_ctx
            .get_cipher_data()
            .expect("Could not get key handle");
        assert!(handle != 0);
        assert!(ENGINE_KEY_HANDLE_TABLE.get_aes_key(handle).is_ok());
        Ok(())
    }

    fn validate_ctx_init_with_iv(aes_type: AesType) -> TestResult<()> {
        let engine = load_engine();
        let cipher = get_cipher(&engine, aes_type.nid());
        let mut rng = thread_rng();

        let cipher_ctx: EvpCipherCtx = EvpCipherCtx::new().expect("Could not make cipher ctx");

        let iv_len = aes_type.iv_len() as usize;
        let mut iv = vec![0; iv_len];
        rng.fill_bytes(&mut iv);

        let result = cipher_ctx.init(cipher, &engine, None, Some(&iv), 1);
        assert!(result.is_ok());
        let handle = cipher_ctx
            .get_cipher_data()
            .expect("Could not get key handle");
        assert!(handle != 0);
        let key_ctx = ENGINE_KEY_HANDLE_TABLE
            .get_aes_key(handle)
            .expect("Could not get key ctx");
        let iv_set = key_ctx.get_iv();
        assert!(iv_set == iv.to_vec());

        assert!(ENGINE_KEY_HANDLE_TABLE.get_aes_key(handle).is_ok());

        Ok(())
    }

    fn create_ctx_with_rand_key(
        cipher: &EvpCipherMethod,
        e: &Engine,
        iv: Option<&[u8]>,
        enc: i32,
        init_ctx: bool,
    ) -> EvpCipherCtx {
        let cipher_ctx: EvpCipherCtx = EvpCipherCtx::new().expect("Could not make cipher ctx");

        let result = cipher_ctx.init(cipher, e, None, None, 1);
        assert!(result.is_ok());

        let key_handle1 = cipher_ctx
            .get_cipher_data()
            .expect("Could not get key handle");
        assert!(key_handle1 != 0);

        let result = aes_ctrl_cb(&cipher_ctx, CipherCtrlOp::RandKey);
        let key_handle2 = match result {
            Ok(CipherCtrlResult::KeyHandle(handle)) => handle,
            _ => {
                panic!("Could not generate key");
            }
        };
        assert!(key_handle1 == key_handle2);
        assert!(ENGINE_KEY_HANDLE_TABLE.get_aes_key(key_handle2).is_ok());

        let key_handle_set = cipher_ctx
            .get_cipher_data()
            .expect("Could not get key handle");
        assert!(key_handle_set == key_handle2);

        if init_ctx {
            // Init ctx with generated key handle2
            let key_bytes = key_handle2.to_be_bytes();
            let result = cipher_ctx.init(cipher, e, Some(&key_bytes), iv, enc);
            assert!(result.is_ok());

            let key_handle_set = cipher_ctx
                .get_cipher_data()
                .expect("Could not get key handle");
            assert!(key_handle_set == key_handle2);
            assert!(ENGINE_KEY_HANDLE_TABLE.get_aes_key(key_handle_set).is_ok());
        }

        cipher_ctx
    }

    fn validate_ctx_keygen_multi(aes_type: AesType) -> TestResult<()> {
        let engine = load_engine();
        let cipher = get_cipher(&engine, aes_type.nid());
        let cipher_ctx = create_ctx_with_rand_key(cipher, &engine, None, 1, false);

        let key_handle1 = cipher_ctx
            .get_cipher_data()
            .expect("Could not get key handle");

        // Generate another Key on the same ctx
        let result = aes_ctrl_cb(&cipher_ctx, CipherCtrlOp::RandKey);
        let key_handle2 = match result {
            Ok(CipherCtrlResult::KeyHandle(handle)) => handle,
            _ => {
                panic!("Could not generate key");
            }
        };
        assert!(ENGINE_KEY_HANDLE_TABLE.get_aes_key(key_handle1).is_err());
        assert!(ENGINE_KEY_HANDLE_TABLE.get_aes_key(key_handle2).is_ok());
        Ok(())
    }

    fn validate_ctx_keygen_init(aes_type: AesType) -> TestResult<()> {
        let engine = load_engine();
        let cipher = get_cipher(&engine, aes_type.nid());
        let cipher_ctx = create_ctx_with_rand_key(cipher, &engine, None, 1, true);
        assert!(cipher_ctx.get_cipher_data().unwrap() != 0);
        Ok(())
    }

    fn validate_ctx_keygen_init_multi(aes_type: AesType) -> OpenSSLResult<()> {
        let engine = load_engine();
        let cipher = get_cipher(&engine, aes_type.nid());
        let cipher_ctx = create_ctx_with_rand_key(cipher, &engine, None, 1, true);
        // Both cipher data and key handle should be set
        let key_handle1 = cipher_ctx
            .get_cipher_data()
            .expect("Could not get key handle");

        assert!(ENGINE_KEY_HANDLE_TABLE.get_aes_key(key_handle1).is_ok());

        // Generate another Key and init with it
        let result = aes_ctrl_cb(&cipher_ctx, CipherCtrlOp::RandKey);
        let key_handle2 = match result {
            Ok(CipherCtrlResult::KeyHandle(handle)) => handle,
            _ => {
                panic!("Could not generate key");
            }
        };
        assert!(ENGINE_KEY_HANDLE_TABLE.get_aes_key(key_handle2).is_ok());
        assert!(ENGINE_KEY_HANDLE_TABLE.get_aes_key(key_handle1).is_err());

        let key_bytes2 = key_handle2.to_be_bytes();

        // Init with newkey handle
        let result = cipher_ctx.init(cipher, &engine, Some(&key_bytes2), None, 1);
        assert!(result.is_ok());

        let cur_key_handle = cipher_ctx.get_cipher_data().unwrap();
        assert!(ENGINE_KEY_HANDLE_TABLE.get_aes_key(key_handle1).is_err());
        assert!(ENGINE_KEY_HANDLE_TABLE.get_aes_key(key_handle2).is_ok());
        assert!(cur_key_handle == key_handle2);
        Ok(())
    }

    fn validate_ctx_keygen_init_deleted_key(aes_type: AesType) -> TestResult<()> {
        let engine = load_engine();
        let cipher = get_cipher(&engine, aes_type.nid());
        let cipher_ctx = create_ctx_with_rand_key(cipher, &engine, None, 1, true);
        // Both cipher data and key handle should be set
        let key_handle1 = cipher_ctx
            .get_cipher_data()
            .expect("Could not get key handle");

        assert!(ENGINE_KEY_HANDLE_TABLE.get_aes_key(key_handle1).is_ok());

        // Generate another Key and init with it
        let result = aes_ctrl_cb(&cipher_ctx, CipherCtrlOp::RandKey);
        let key_handle2 = match result {
            Ok(CipherCtrlResult::KeyHandle(handle)) => handle,
            _ => {
                panic!("Could not generate key");
            }
        };
        assert!(ENGINE_KEY_HANDLE_TABLE.get_aes_key(key_handle2).is_ok());
        assert!(ENGINE_KEY_HANDLE_TABLE.get_aes_key(key_handle1).is_err());

        let key_bytes2 = key_handle2.to_be_bytes();

        // Init with newkey handle
        let result = cipher_ctx.init(cipher, &engine, Some(&key_bytes2), None, 1);
        assert!(result.is_ok());

        let cur_key_handle = cipher_ctx.get_cipher_data().unwrap();
        assert!(ENGINE_KEY_HANDLE_TABLE.get_aes_key(key_handle2).is_ok());
        assert!(cur_key_handle == key_handle2);

        let key_bytes1 = key_handle1.to_be_bytes();

        let result = cipher_ctx.init(cipher, &engine, Some(&key_bytes1), None, 1);
        assert!(result.is_err(), "result {:?}", result);

        Ok(())
    }

    fn validate_ctx_copy(aes_type: AesType) -> TestResult<()> {
        let engine = load_engine();
        let cipher = get_cipher(&engine, aes_type.nid());
        let cipher_ctx1: EvpCipherCtx = create_ctx_with_rand_key(cipher, &engine, None, 1, true);
        // Both cipher data and key handle should be set
        let key_handle1 = cipher_ctx1
            .get_cipher_data()
            .expect("Could not get key handle");
        let aes_key_ctx1 = ENGINE_KEY_HANDLE_TABLE
            .get_aes_key(key_handle1)
            .expect("Could not get key ctx");

        let cipher_ctx2: EvpCipherCtx = EvpCipherCtx::new().expect("Could not make cipher ctx");

        let result = cipher_ctx2.init(cipher, &engine, None, None, 1);
        assert!(result.is_ok());

        let result = aes_ctrl_cb(&cipher_ctx1, CipherCtrlOp::CtxCopy(&cipher_ctx2))
            .expect("Could not copy ctx");
        assert_eq!(result, CipherCtrlResult::CopySuccess);

        let key_handle2 = cipher_ctx2
            .get_cipher_data()
            .expect("Could not get key handle");
        let aes_key_ctx2 = ENGINE_KEY_HANDLE_TABLE
            .get_aes_key(key_handle2)
            .expect("Could not get key ctx");

        let iv1 = aes_key_ctx1.get_iv();
        let iv2 = aes_key_ctx2.get_iv();
        assert_eq!(iv1, iv2);

        drop(cipher_ctx1);

        let key_handle2 = cipher_ctx2
            .get_cipher_data()
            .expect("Could not get key handle");
        assert!(ENGINE_KEY_HANDLE_TABLE.get_aes_key(key_handle2).is_ok());
        Ok(())
    }

    fn validate_ctx_aes_cbc_cipher(aes_type: AesType) -> TestResult<()> {
        let mut rng = thread_rng();
        let engine = load_engine();
        let cipher = get_cipher(&engine, aes_type.nid());
        let mut iv = [0; AES_CBC_IV_LEN];
        rng.fill_bytes(&mut iv);

        // init ctx with rand key for encryption.
        let cipher_ctx = create_ctx_with_rand_key(cipher, &engine, Some(&iv), 1, true);

        let mut data = vec![0u8; 1024];
        rng.fill_bytes(&mut data);

        // Encrypt
        let result = aes_cbc_do_cipher_cb(&cipher_ctx, data.clone());
        assert!(result.is_ok());
        let cipher_text = result.unwrap();
        assert!(data != cipher_text);

        // Init ctx for decryption
        let result = cipher_ctx.init(cipher, &engine, None, Some(&iv), 0);
        assert!(result.is_ok());

        // Decrypt
        let result = aes_cbc_do_cipher_cb(&cipher_ctx, cipher_text.clone());
        assert!(result.is_ok());
        let decrypted_data = result.unwrap();
        assert_eq!(data, decrypted_data);
        Ok(())
    }

    fn validate_ctx_aes_cbc_cipher_multiblock(aes_type: AesType) -> TestResult<()> {
        let mut rng = thread_rng();
        let engine = load_engine();
        let cipher = get_cipher(&engine, aes_type.nid());
        let mut iv = [0; AES_CBC_IV_LEN];
        rng.fill_bytes(&mut iv);

        // init ctx with rand key for encryption.
        let cipher_ctx = create_ctx_with_rand_key(cipher, &engine, Some(&iv), 1, true);

        // Encrypt data1 and data2 separately
        let mut data1 = vec![0u8; 128];
        rng.fill_bytes(&mut data1);

        let result = aes_cbc_do_cipher_cb(&cipher_ctx, data1.clone());
        assert!(result.is_ok());
        let cipher_text1 = result.unwrap();
        assert!(data1 != cipher_text1);

        let mut data2 = vec![0u8; 256];
        rng.fill_bytes(&mut data2);

        let result = aes_cbc_do_cipher_cb(&cipher_ctx, data2.clone());
        assert!(result.is_ok());
        let cipher_text2 = result.unwrap();
        assert!(data2 != cipher_text2);

        let mut total_data = vec![0u8; 384];
        total_data[..128].copy_from_slice(data1.as_slice());
        total_data[128..].copy_from_slice(data2.as_slice());

        // Combine the cipher text
        let mut total_encrypted = vec![0u8; 384];
        total_encrypted[..128].copy_from_slice(cipher_text1.as_slice());
        total_encrypted[128..].copy_from_slice(cipher_text2.as_slice());

        // Init ctx for decryption
        let result = cipher_ctx.init(cipher, &engine, None, Some(&iv), 0);
        assert!(result.is_ok());

        // Decrypt entire blob
        let result = aes_cbc_do_cipher_cb(&cipher_ctx, total_encrypted.clone());
        assert!(result.is_ok());
        let decrypted_data = result.unwrap();
        assert_eq!(total_data, decrypted_data);
        Ok(())
    }

    fn validate_ctx_aes_cbc_cipher_corrupt_data(aes_type: AesType) -> TestResult<()> {
        let mut rng = thread_rng();
        let engine = load_engine();
        let cipher = get_cipher(&engine, aes_type.nid());
        let mut iv = [0; AES_CBC_IV_LEN];
        rng.fill_bytes(&mut iv);

        // init ctx with rand key for encryption.
        let cipher_ctx = create_ctx_with_rand_key(cipher, &engine, Some(&iv), 1, true);

        let mut data = vec![0u8; 1024];
        rng.fill_bytes(&mut data);

        let result = aes_cbc_do_cipher_cb(&cipher_ctx, data.clone());
        assert!(result.is_ok());
        let cipher_text = result.unwrap();
        assert!(data != cipher_text);

        // Corrupt the data
        let mut corrupt_data = cipher_text.clone();
        corrupt_data[0] ^= 0x1;
        assert!(corrupt_data != cipher_text);

        // Init with ctx for decryption
        let result = cipher_ctx.init(cipher, &engine, None, Some(&iv), 0);
        assert!(result.is_ok());

        let result = aes_cbc_do_cipher_cb(&cipher_ctx, corrupt_data.clone());
        assert!(result.is_ok());
        let decrypted_data = result.unwrap();
        assert!(cipher_text != decrypted_data);
        assert!(data != decrypted_data);
        Ok(())
    }

    fn validate_ctx_aes_cbc_cipher_unaligned_data(aes_type: AesType) -> TestResult<()> {
        let mut rng = thread_rng();
        let engine = load_engine();
        let cipher = get_cipher(&engine, aes_type.nid());
        let mut iv = [0; AES_CBC_IV_LEN];
        rng.fill_bytes(&mut iv);

        // init ctx with rand key for encryption.
        let cipher_ctx = create_ctx_with_rand_key(cipher, &engine, Some(&iv), 1, true);

        let mut data = vec![0u8; 100];
        rng.fill_bytes(&mut data);

        // Encrypt
        let result = aes_cbc_do_cipher_cb(&cipher_ctx, data.clone());
        assert!(result.is_err(), "result {:?}", result);
        Ok(())
    }

    fn validate_ctx_aes_cbc_cipher_invalid_datasize(aes_type: AesType) -> TestResult<()> {
        let mut rng = thread_rng();
        let engine = load_engine();
        let cipher = get_cipher(&engine, aes_type.nid());
        let mut iv = [0; AES_CBC_IV_LEN];
        rng.fill_bytes(&mut iv);

        // Init ctx with rand key for encryption.
        let cipher_ctx = create_ctx_with_rand_key(cipher, &engine, Some(&iv), 1, true);

        let mut data = vec![0u8; 1025];
        rng.fill_bytes(&mut data);

        // Encrypt
        let result = aes_cbc_do_cipher_cb(&cipher_ctx, data.clone());
        assert!(result.is_err(), "result {:?}", result);
        Ok(())
    }

    fn validate_ctx_aes_cbc_cipher_invalid_key(aes_type: AesType) -> TestResult<()> {
        let mut rng = thread_rng();
        let engine = load_engine();
        let cipher = get_cipher(&engine, aes_type.nid());
        let mut iv = [0; AES_CBC_IV_LEN];
        rng.fill_bytes(&mut iv);

        // Create ctx with rand key for encryption.
        let cipher_ctx = create_ctx_with_rand_key(cipher, &engine, Some(&iv), 1, true);

        let mut data = vec![0u8; 1024];
        rng.fill_bytes(&mut data);

        let result = aes_cbc_do_cipher_cb(&cipher_ctx, data.clone());
        assert!(result.is_ok());
        let cipher_text = result.unwrap();
        assert!(data != cipher_text);

        // Init ctx decryption with different key handle
        let result = aes_ctrl_cb(&cipher_ctx, CipherCtrlOp::RandKey);
        let key_handle2 = match result {
            Ok(CipherCtrlResult::KeyHandle(handle)) => handle,
            _ => {
                panic!("Could not generate key");
            }
        };
        assert!(key_handle2 != 0);

        let key_bytes2 = key_handle2.to_be_bytes();
        let result = cipher_ctx.init(cipher, &engine, Some(&key_bytes2), Some(&iv), 0);
        assert!(result.is_ok());

        let result = aes_cbc_do_cipher_cb(&cipher_ctx, cipher_text.clone());
        assert!(result.is_ok());
        let decrypted_data = result.unwrap();
        assert!(cipher_text != decrypted_data);
        assert!(data != decrypted_data);
        Ok(())
    }

    #[cfg(feature = "gcm")]
    fn validate_ctx_aes_gcm_cipher(aad: bool) -> TestResult<()> {
        let mut rng = thread_rng();
        let engine = load_engine();
        let cipher = get_cipher(&engine, AesType::Aes256Gcm.nid());
        let mut iv = [0; AES_GCM_IV_LEN];
        rng.fill_bytes(&mut iv);
        let cipher_ctx = create_ctx_with_rand_key(cipher, &engine, Some(&iv), 1, true);

        let mut data = vec![0u8; 64];
        rng.fill_bytes(&mut data);
        let mut aad_data = vec![0u8; 32];
        rng.fill_bytes(&mut aad_data);

        if aad {
            let result = aes_gcm_do_cipher_cb(&cipher_ctx, aad_data.clone(), true);
            assert!(result.is_ok());
        }

        // Encrypt
        let result = aes_gcm_do_cipher_cb(&cipher_ctx, data.clone(), false);
        assert!(result.is_ok());
        let cipher_text = result.unwrap().expect("Could not get encrypted data");
        assert!(data != cipher_text);

        // Init ctx for decryption
        let key_handle = cipher_ctx
            .get_cipher_data()
            .expect("Could not get key handle");
        let key_bytes = key_handle.to_be_bytes();
        let result = cipher_ctx.init(cipher, &engine, Some(&key_bytes), Some(&iv), 0);
        assert!(result.is_ok());

        if aad {
            let result = aes_gcm_do_cipher_cb(&cipher_ctx, aad_data.clone(), true);
            assert!(result.is_ok());
        }

        // Decrypt
        let result = aes_gcm_do_cipher_cb(&cipher_ctx, cipher_text.clone(), false);
        assert!(result.is_ok());
        let decrypted_data = result.unwrap().expect("Could not get decrypted data");
        assert_eq!(data, decrypted_data);
        Ok(())
    }

    #[cfg(feature = "xts")]
    fn validate_ctx_aes_xts_cipher() -> TestResult<()> {
        let mut rng = thread_rng();
        let engine = load_engine();
        let cipher = get_cipher(&engine, AesType::Aes256Xts.nid());
        let mut iv = [0; AES_CBC_IV_LEN];
        rng.fill_bytes(&mut iv);

        // init ctx with rand key for encryption.
        let cipher_ctx = create_ctx_with_rand_key(cipher, &engine, Some(&iv), 1, true);

        let mut data = vec![0u8; 1024 * 1024];
        rng.fill_bytes(&mut data);

        // Encrypt
        let result = aes_xts_do_cipher_cb(&cipher_ctx, data.clone());
        assert!(result.is_ok());
        let cipher_text = result.unwrap();
        assert!(data != cipher_text);

        // Init ctx for decryption
        let result = cipher_ctx.init(cipher, &engine, None, Some(&iv), 0);
        assert!(result.is_ok());

        // Decrypt
        let result = aes_xts_do_cipher_cb(&cipher_ctx, cipher_text.clone());
        assert!(result.is_ok());
        let decrypted_data = result.unwrap();
        assert_eq!(data, decrypted_data);
        Ok(())
    }
}
