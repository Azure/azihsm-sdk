// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

/// Generates an RSA key pair configured for RSA-AES wrapping and unwrapping.
pub(crate) fn get_rsa_unwrapping_key_pair(
    session: &HsmSession,
) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("Failed to build RSA unwrapping private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("Failed to build RSA wrapping public key props");

    let mut algo = HsmRsaKeyUnwrappingKeyGenAlgo::default();

    HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
        .expect("Failed to generate RSA unwrapping key pair")
}

/// Describes what operations the imported RSA key pair should support.
#[derive(Clone, Copy)]
pub(crate) enum ImportedRsaKeyUsage {
    SignVerify,
    EncryptDecrypt,
}

/// Common helper that imports RSA private-key DER into HSM RSA key handles
/// through RSA-AES wrap/unwrap.
pub(crate) fn try_import_rsa_key_pair(
    session: &HsmSession,
    der: &[u8],
    bits: u32,
    usage: ImportedRsaKeyUsage,
    is_session: bool,
) -> Result<(HsmRsaPrivateKey, HsmRsaPublicKey), HsmError> {
    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(session);

    let (can_sign, can_verify, can_decrypt, can_encrypt) = match usage {
        ImportedRsaKeyUsage::SignVerify => (true, true, false, false),
        ImportedRsaKeyUsage::EncryptDecrypt => (false, false, true, true),
    };

    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_sign(can_sign)
        .can_decrypt(can_decrypt)
        .is_session(is_session)
        .build()
        .expect("Failed to build imported RSA private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_verify(can_verify)
        .can_encrypt(can_encrypt)
        .is_session(is_session)
        .build()
        .expect("Failed to build imported RSA public key props");

    let hash_algo = HsmHashAlgo::Sha384;
    let kek_size = 32;

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(hash_algo, kek_size);
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, der)
        .expect("Failed to RSA-AES wrap RSA DER key");

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(hash_algo);

    HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        &wrapped_key,
        priv_key_props,
        pub_key_props,
    )
}
