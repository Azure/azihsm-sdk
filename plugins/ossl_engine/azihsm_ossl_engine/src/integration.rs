// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration-test helpers for the engine crate.
//!
//! Gated behind the `integration` feature; not part of the production engine —
//! the cdylib OpenSSL loads is built without this feature.

use azihsm_api::HsmEccCurve;
use azihsm_api::HsmEccKeyGenAlgo;
use azihsm_api::HsmEncrypter;
use azihsm_api::HsmHashAlgo;
use azihsm_api::HsmKeyClass;
use azihsm_api::HsmKeyCommonProps;
use azihsm_api::HsmKeyKind;
use azihsm_api::HsmKeyManager;
use azihsm_api::HsmKeyProps;
use azihsm_api::HsmKeyPropsBuilder;
use azihsm_api::HsmRsaAesWrapAlgo;
use azihsm_api::HsmRsaKeyRsaAesKeyUnwrapAlgo;
use azihsm_api::HsmRsaKeyUnwrappingKeyGenAlgo;
use azihsm_api::HsmRsaPrivateKey;
use azihsm_api::HsmRsaPublicKey;
use azihsm_api::HsmSession;
use azihsm_crypto::ExportableKey;
use azihsm_crypto::ImportableKey;
use azihsm_crypto::Key;
use azihsm_ossl_engine_core::error::EngineError;
use azihsm_ossl_engine_core::error::EngineResult;
use zeroize::Zeroizing;

use crate::context::EngineData;

/// Open the HSM from the ambient `AZIHSM_*` environment, generate a persistent
/// EC P-384 key, and return its masked blob — the form the loader consumes.
/// Reuses the engine's real open path so a generated blob and a later
/// `ENGINE_load_private_key` share the same masking (via the persisted BMK under
/// the shared resiliency storage dir).
pub fn generate_masked_ec_p384_from_env() -> EngineResult<Vec<u8>> {
    let data = EngineData::new();
    data.open_hsm_from_env()?;
    data.with_session(|session| {
        let build = |class: HsmKeyClass, sign: bool| {
            HsmKeyPropsBuilder::default()
                .class(class)
                .key_kind(HsmKeyKind::Ecc)
                .ecc_curve(HsmEccCurve::P384)
                .is_session(false)
                .can_sign(sign)
                .can_verify(!sign)
                .build()
                .map_err(|e| EngineError::wrap("build EC key props", e))
        };
        let priv_props = build(HsmKeyClass::Private, true)?;
        let pub_props = build(HsmKeyClass::Public, false)?;
        let mut algo = HsmEccKeyGenAlgo::default();
        let (priv_key, _pub) =
            HsmKeyManager::generate_key_pair(session, &mut algo, priv_props, pub_props)
                .map_err(|e| EngineError::wrap("generate EC key pair", e))?;
        priv_key
            .masked_key_vec()
            .map_err(|e| EngineError::wrap("export masked key", e))
    })
}

/// Usage profile for an imported RSA key pair: private sign / public verify,
/// or private decrypt / public encrypt.
#[derive(Clone, Copy)]
pub enum RsaKeyUsage {
    Sign,
    Decrypt,
}

/// An imported RSA key: the private key's masked blob (the form
/// `ENGINE_load_private_key` consumes) and the public half as
/// SubjectPublicKeyInfo DER.
pub struct RsaImport {
    pub masked_key: Vec<u8>,
    pub public_key_der: Vec<u8>,
}

/// AES-256 KEK for RSA-AES key wrap, matching the provider's import contract
/// (SHA-256 OAEP + MGF1, AES-256 KWP).
const RSA_AES_WRAP_KEK_BYTES: usize = 32;

fn rsa_import_props(bits: u32, usage: RsaKeyUsage) -> EngineResult<(HsmKeyProps, HsmKeyProps)> {
    let (sign, decrypt) = match usage {
        RsaKeyUsage::Sign => (true, false),
        RsaKeyUsage::Decrypt => (false, true),
    };
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .is_session(false)
        .can_sign(sign)
        .can_decrypt(decrypt)
        .build()
        .map_err(|e| EngineError::wrap("build RSA private key props", e))?;
    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .is_session(false)
        .can_verify(sign)
        .can_encrypt(decrypt)
        .build()
        .map_err(|e| EngineError::wrap("build RSA public key props", e))?;
    Ok((priv_props, pub_props))
}

/// Get the HSM's RSA-AES unwrapping key pair (generated and cached by the
/// device; fixed at 2048 bits). The public half wraps keys for import, the
/// private half unwraps them inside the HSM.
fn hsm_unwrapping_key_pair(
    session: &HsmSession,
) -> EngineResult<(HsmRsaPrivateKey, HsmRsaPublicKey)> {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .map_err(|e| EngineError::wrap("build unwrapping private key props", e))?;
    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .map_err(|e| EngineError::wrap("build wrapping public key props", e))?;
    let mut algo = HsmRsaKeyUnwrappingKeyGenAlgo::default();
    HsmKeyManager::generate_key_pair(session, &mut algo, priv_props, pub_props)
        .map_err(|e| EngineError::wrap("get HSM unwrapping key pair", e))
}

/// Unwrap an RSA-AES wrapped key pair into the HSM and export the private
/// key's masked blob plus the public half's SPKI DER.
fn unwrap_rsa_and_mask(
    session: &HsmSession,
    wrapped: &[u8],
    bits: u32,
    usage: RsaKeyUsage,
) -> EngineResult<RsaImport> {
    let (unwrapping_priv, _unwrapping_pub) = hsm_unwrapping_key_pair(session)?;
    let (priv_props, pub_props) = rsa_import_props(bits, usage)?;
    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let (priv_key, pub_key) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrapping_priv,
        wrapped,
        priv_props,
        pub_props,
    )
    .map_err(|e| EngineError::wrap("unwrap RSA key into HSM", e))?;
    let masked_key = priv_key
        .masked_key_vec()
        .map_err(|e| EngineError::wrap("export masked RSA key", e))?;
    let public_key_der = pub_key
        .pub_key_der_vec()
        .map_err(|e| EngineError::wrap("export RSA public key DER", e))?;
    Ok(RsaImport {
        masked_key,
        public_key_der,
    })
}

pub(crate) fn import_rsa_der(
    session: &HsmSession,
    der: &[u8],
    usage: RsaKeyUsage,
) -> EngineResult<RsaImport> {
    // Parse to derive the modulus size and re-encode as canonical PKCS#8 —
    // the only private-key format the HSM's unwrap accepts.
    let key = azihsm_crypto::RsaPrivateKey::from_bytes(der)
        .map_err(|e| EngineError::wrap("parse RSA private key DER", e))?;
    let bits = u32::try_from(key.size())
        .ok()
        .and_then(|bytes| bytes.checked_mul(8))
        .ok_or_else(|| EngineError::Other("RSA modulus size overflows u32".into()))?;
    let pkcs8 = Zeroizing::new(
        key.to_vec()
            .map_err(|e| EngineError::wrap("encode RSA key as PKCS#8", e))?,
    );

    let (_unwrapping_priv, unwrapping_pub) = hsm_unwrapping_key_pair(session)?;
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, RSA_AES_WRAP_KEK_BYTES);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub, &pkcs8)
        .map_err(|e| EngineError::wrap("RSA-AES wrap key for import", e))?;
    unwrap_rsa_and_mask(session, &wrapped, bits, usage)
}

/// Import a plaintext RSA private key (PKCS#1 or PKCS#8 DER): wrap it against
/// the HSM's unwrapping key, unwrap it into the HSM, and return the masked
/// blob + public key.
pub fn import_masked_rsa_from_der_env(der: &[u8], usage: RsaKeyUsage) -> EngineResult<RsaImport> {
    let data = EngineData::new();
    data.open_hsm_from_env()?;
    data.with_session(|session| import_rsa_der(session, der, usage))
}

/// Import a pre-wrapped RSA key blob (`[RSA-OAEP encrypted KEK || AES-KWP
/// wrapped PKCS#8]`, SHA-256 OAEP, AES-256 KEK). The blob is opaque, so the
/// caller supplies the modulus size.
pub fn import_masked_rsa_from_wrapped_env(
    wrapped: &[u8],
    bits: u32,
    usage: RsaKeyUsage,
) -> EngineResult<RsaImport> {
    let data = EngineData::new();
    data.open_hsm_from_env()?;
    data.with_session(|session| unwrap_rsa_and_mask(session, wrapped, bits, usage))
}

/// Export the HSM's RSA-AES wrapping public key as SPKI DER, for wrapping
/// keys offline before a `import_masked_rsa_from_wrapped_env` import.
pub fn rsa_wrapping_public_key_from_env() -> EngineResult<Vec<u8>> {
    let data = EngineData::new();
    data.open_hsm_from_env()?;
    data.with_session(|session| {
        let (_priv, pub_key) = hsm_unwrapping_key_pair(session)?;
        pub_key
            .pub_key_der_vec()
            .map_err(|e| EngineError::wrap("export wrapping public key DER", e))
    })
}

#[cfg(all(test, feature = "mock"))]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_api::HsmCredentials;
    use azihsm_api::HsmRsaKeyUnmaskAlgo;
    use azihsm_crypto::HashAlgo;
    use azihsm_crypto::RsaAesKeyWrap;
    use azihsm_crypto::WrapOp;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use serial_test::serial;

    use super::*;
    use crate::context::DEFAULT_CRED_ID;
    use crate::context::DEFAULT_CRED_PIN;
    use crate::context::test_support::Scratch;
    use crate::context::test_support::caller_settings;

    fn open_data(scratch: &Scratch) -> EngineData {
        let data = EngineData::new();
        data.open_hsm_with(
            caller_settings(scratch),
            HsmCredentials::new(&DEFAULT_CRED_ID, &DEFAULT_CRED_PIN),
        )
        .unwrap();
        data
    }

    /// Assert the masked blob unmasks to an RSA pair with the expected size
    /// and usage flags.
    fn assert_unmasks(data: &EngineData, import: &RsaImport, bits: u32, usage: RsaKeyUsage) {
        data.with_session(|session| {
            let mut unmask_algo = HsmRsaKeyUnmaskAlgo::default();
            let (priv_key, pub_key) =
                HsmKeyManager::unmask_key_pair(session, &mut unmask_algo, &import.masked_key)
                    .unwrap();
            assert_eq!(priv_key.kind(), HsmKeyKind::Rsa);
            assert_eq!(priv_key.bits(), bits);
            assert_eq!(pub_key.kind(), HsmKeyKind::Rsa);
            assert_eq!(priv_key.can_sign(), matches!(usage, RsaKeyUsage::Sign));
            assert_eq!(
                priv_key.can_decrypt(),
                matches!(usage, RsaKeyUsage::Decrypt)
            );
            assert_eq!(pub_key.can_verify(), matches!(usage, RsaKeyUsage::Sign));
            assert_eq!(pub_key.can_encrypt(), matches!(usage, RsaKeyUsage::Decrypt));
            Ok(())
        })
        .unwrap();
    }

    /// Plain-DER import: the masked blob round-trips through unmask and the
    /// exported public half matches the input key's.
    #[test]
    #[serial]
    fn import_rsa_der_masks_and_unmasks() {
        let scratch = Scratch::new("rsa-der");
        let data = open_data(&scratch);

        let pkey = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let der = pkey.private_key_to_pkcs8().unwrap();

        let import = data
            .with_session(|session| import_rsa_der(session, &der, RsaKeyUsage::Sign))
            .unwrap();

        assert!(!import.masked_key.is_empty());
        assert_eq!(import.public_key_der, pkey.public_key_to_der().unwrap());
        assert_unmasks(&data, &import, 2048, RsaKeyUsage::Sign);
    }

    /// Wrapped-blob import: wrap in software against the exported wrapping
    /// public key (as an offline wrapper would), then import the opaque blob.
    #[test]
    #[serial]
    fn import_rsa_wrapped_software_wrap_roundtrips() {
        let scratch = Scratch::new("rsa-wrapped");
        let data = open_data(&scratch);

        let wrapping_pub_der = data
            .with_session(|session| {
                let (_priv, pub_key) = hsm_unwrapping_key_pair(session)?;
                pub_key
                    .pub_key_der_vec()
                    .map_err(|e| EngineError::wrap("export wrapping key", e))
            })
            .unwrap();

        let pkey = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let target =
            azihsm_crypto::RsaPrivateKey::from_bytes(&pkey.private_key_to_pkcs8().unwrap())
                .unwrap();
        let wrapping_pub = azihsm_crypto::RsaPublicKey::from_bytes(&wrapping_pub_der).unwrap();

        let mut kw = RsaAesKeyWrap::new(HashAlgo::sha256(), RSA_AES_WRAP_KEK_BYTES);
        let len = kw.wrap_key(&wrapping_pub, &target, None).unwrap();
        let mut wrapped = vec![0u8; len];
        let len = kw
            .wrap_key(&wrapping_pub, &target, Some(&mut wrapped))
            .unwrap();
        wrapped.truncate(len);

        let import = data
            .with_session(|session| {
                unwrap_rsa_and_mask(session, &wrapped, 2048, RsaKeyUsage::Decrypt)
            })
            .unwrap();

        assert_eq!(import.public_key_der, pkey.public_key_to_der().unwrap());
        assert_unmasks(&data, &import, 2048, RsaKeyUsage::Decrypt);
    }

    /// Full RSA load round trip: import an external key, write its masked
    /// blob, load it back through the engine's `load_private_key` path, and
    /// verify the returned EVP_PKEY carries the matching public key.
    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn load_rsa_key_round_trips_through_engine() {
        use azihsm_ossl_engine_core::ffi;
        use foreign_types::ForeignType;

        let scratch = Scratch::new("rsa-load");
        let data = open_data(&scratch);

        let pkey = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let der = pkey.private_key_to_pkcs8().unwrap();
        let import = data
            .with_session(|session| import_rsa_der(session, &der, RsaKeyUsage::Sign))
            .unwrap();

        let blob_path = scratch.0.join("rsa_key.bin");
        crate::context::write_key_material(&blob_path, &import.masked_key).unwrap();

        let (engine, engine_raw) = crate::context::new_test_engine();
        let uri = format!("azihsm://{};type=rsa", blob_path.display());
        let raw = crate::keyload::load_key(&engine, &data, &uri).unwrap();
        assert!(!raw.is_null());

        // Take ownership of the returned EVP_PKEY and confirm its public key.
        // SAFETY: raw is an owning *mut EVP_PKEY returned by load_key.
        let loaded: PKey<openssl::pkey::Public> = unsafe { PKey::from_ptr(raw.cast()) };
        assert_eq!(
            loaded.public_key_to_der().unwrap(),
            pkey.public_key_to_der().unwrap()
        );
        drop(loaded);

        // Release the test engine's structural ref; the loaded key already
        // released its functional ref when dropped above.
        // SAFETY: engine_raw is the ENGINE_new ref from new_test_engine.
        unsafe { ffi::ENGINE_free(engine_raw) };
    }
}
