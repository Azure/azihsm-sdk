// Copyright (C) Microsoft Corporation. All rights reserved.
mod common;

use mcr_api::*;
use test_with_tracing::test;

use crate::common::*;

fn unwrap_raw_key_into_device(
    app_session: &HsmSession,
    import_key_der: &[u8],
    key_class: KeyClass,
    hash_algorithm: DigestKind,
    target_key_usage: KeyUsage,
) -> HsmResult<HsmKeyHandle> {
    // Get handle to private wrapping key
    let wrapping_key = get_unwrapping_key(app_session);

    let result = app_session.export_public_key(&wrapping_key);
    assert!(result.is_ok(), "result {:?}", result);
    let wrapping_key_der = result.unwrap();

    let wrapped_blob = wrap_data(wrapping_key_der, import_key_der);

    // Unwrap key in wrapped_blob
    let wrapped_blob_params = RsaUnwrapParams {
        key_class,
        padding: RsaCryptoPadding::Oaep,
        hash_algorithm,
    };

    app_session.rsa_unwrap(
        &wrapping_key,
        wrapped_blob,
        wrapped_blob_params,
        None,
        KeyProperties {
            key_usage: target_key_usage,
            key_availability: KeyAvailability::App,
        },
    )
}

fn ecc_raw_pub_key_from_der(der: &[u8]) -> Vec<u8> {
    use sec1::der::Decode;

    let public_key_info = spki::SubjectPublicKeyInfoRef::from_der(der).unwrap();
    let public_key_der = public_key_info.subject_public_key;

    public_key_der.raw_bytes()[1..].to_vec() // Remove the leading SEC1 tag byte
}

#[test]
fn test_api_compat_ecc_sign_256() {
    api_test(common_setup, common_cleanup, |device, _path| {
        // Generate a known key locally
        let (priv_key_der, pub_key_der) = generate_ecc_der(KeyType::Ecc256Private);

        // Generate data to sign
        use crypto::sha::sha;
        let message_raw = generate_random_vector(20);
        let result = sha(crypto::sha::HashAlgorithm::Sha256, &message_raw);
        assert!(result.is_ok(), "result {:?}", result);
        let digest = result.unwrap();

        let app_session = common_open_app_session(device);

        // Import key into device
        let result = unwrap_raw_key_into_device(
            &app_session,
            &priv_key_der,
            KeyClass::Ecc,
            DigestKind::Sha1,
            KeyUsage::SignVerify,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        // ECC Sign using device
        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();

        // Compat test 1: ECC Verify using API itself
        {
            let result =
                app_session.ecc_verify(&priv_key_handle, digest.clone(), signature.clone());
            assert!(result.is_ok(), "result {:?}", result);
            let result = app_session.delete_key(&priv_key_handle);
            assert!(result.is_ok(), "result {:?}", result);
        }

        // Compat test 2: ECC Verify using OpenSSL
        #[cfg(target_os = "linux")]
        {
            let ecc = openssl::ec::EcKey::public_key_from_der(&pub_key_der).unwrap();
            let pkey = openssl::pkey::PKey::from_ec_key(ecc.clone()).unwrap();

            // Convert the raw signature to DER, which is expected by OpenSSL verify API.
            let signature_len = signature.len();
            let (r, s) = signature.split_at(signature_len / 2);
            let r = openssl::bn::BigNum::from_slice(r).unwrap();
            let s = openssl::bn::BigNum::from_slice(s).unwrap();
            let signature = openssl::ecdsa::EcdsaSig::from_private_components(r, s).unwrap();

            // OpenSSL Method 1
            let result = signature.verify(&digest, &ecc);
            assert!(result.is_ok(), "result {:?}", result);

            // OpenSSL Method 2
            let signature = signature.to_der().unwrap();
            let mut ctx = openssl::pkey_ctx::PkeyCtx::new(&pkey).unwrap();
            ctx.verify_init().unwrap();
            let result = ctx.verify(&digest, &signature).unwrap();
            assert!(result, "result {:?}", result);
        }

        // Compat test 3: ECC Verify using symcrypt
        {
            let raw_pub_key = ecc_raw_pub_key_from_der(&pub_key_der);

            let symcrypt_key = symcrypt::ecc::EcKey::set_public_key(
                symcrypt::ecc::CurveType::NistP256,
                &raw_pub_key,
                symcrypt::ecc::EcKeyUsage::EcDsa,
            )
            .unwrap();

            let result = symcrypt_key.ecdsa_verify(&signature, &digest);
            assert!(result.is_ok(), "result {:?}", result);
        }
    });
}
