// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM RSA import for `openssl genpkey -engine azihsm -algorithm RSA`.
//!
//! The HSM cannot generate RSA keys, so this is an import pipeline (see
//! [`azihsm_ossl_engine_core::rsa_pkey_method`]). An external key enters the
//! HSM wrapped: `azihsm.input_key` gives a plaintext DER the engine wraps
//! against the HSM's unwrapping public key, `azihsm.wrapped_key` gives a
//! pre-wrapped blob (wrapped elsewhere against the exported unwrapping key).
//! Either is unwrapped into the HSM, its masked blob optionally written to
//! `azihsm.masked_key`, and a usable `EVP_PKEY` returned. `key_usage:
//! keyWrapping` instead exports the HSM's unwrapping public key for an
//! external party to wrap against.

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
use azihsm_ossl_engine_core::engine::Engine;
use azihsm_ossl_engine_core::error::EngineError;
use azihsm_ossl_engine_core::error::EngineResult;
use azihsm_ossl_engine_core::ffi;
use azihsm_ossl_engine_core::rsa_pkey_method::RsaImportHandler;
use azihsm_ossl_engine_core::rsa_pkey_method::RsaImportParams;
use azihsm_ossl_engine_core::rsa_pkey_method::RsaKeyUsage;
use openssl::pkey::PKey;
use zeroize::Zeroizing;

use crate::context::EngineData;
use crate::context::delete_hsm_key;
use crate::engine_impl::engine_data_slot;

/// RSA-AES wrap parameters, matching the 3.x provider so a `wrapped_key` blob
/// produced against the exported unwrapping key interoperates: SHA-256
/// OAEP/MGF1 and a 256-bit (32-byte) AES KEK.
const WRAP_HASH: HsmHashAlgo = HsmHashAlgo::Sha256;
const WRAP_KEK_BYTES: usize = 32;

/// Marker type carrying the engine's RSA import logic (see
/// [`RsaImportHandler`]).
pub(crate) struct AzihsmRsaImport;

impl RsaImportHandler for AzihsmRsaImport {
    fn import(
        engine: &Engine,
        params: &RsaImportParams,
        pkey: *mut ffi::EVP_PKEY,
    ) -> EngineResult<()> {
        if params.session {
            return Err(EngineError::Other(
                "azihsm.session:true (session keys) is not yet supported by the engine".into(),
            ));
        }

        let slot = engine_data_slot()?;
        let data = slot
            .get(engine)
            .ok_or(EngineError::NullParam("engine_data"))?;
        // First caller may be the import itself (idempotent open).
        data.open_hsm_from_env()?;

        match params.key_usage {
            RsaKeyUsage::KeyWrapping => export_unwrapping_key(data, params, pkey),
            RsaKeyUsage::DigitalSignature => import_private(engine, data, params, pkey),
        }
    }
}

/// Build the imported key's private/public properties: exclusive
/// digitalSignature usage (sign on the private half, verify on the public).
/// RSA-CRT (unless plain RSA was requested) applies to the private half only;
/// the public half is always kind `Rsa`.
fn import_props(params: &RsaImportParams) -> EngineResult<(HsmKeyProps, HsmKeyProps)> {
    let priv_kind = if params.crt {
        HsmKeyKind::RsaCrt
    } else {
        HsmKeyKind::Rsa
    };
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(priv_kind)
        .bits(params.bits)
        .is_session(false)
        .can_sign(true)
        .build()
        .map_err(|e| EngineError::wrap("build imported private props", e))?;
    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(params.bits)
        .is_session(false)
        .can_verify(true)
        .build()
        .map_err(|e| EngineError::wrap("build imported public props", e))?;
    Ok((priv_props, pub_props))
}

/// Import an external RSA private key (`input_key` or `wrapped_key`) into the
/// HSM and return a usable `EVP_PKEY`.
#[allow(unsafe_code)]
fn import_private(
    engine: &Engine,
    data: &EngineData,
    params: &RsaImportParams,
    pkey: *mut ffi::EVP_PKEY,
) -> EngineResult<()> {
    let source = match (&params.input_key, &params.wrapped_key) {
        (Some(_), Some(_)) => {
            return Err(EngineError::Other(
                "azihsm.input_key and azihsm.wrapped_key are mutually exclusive".into(),
            ));
        }
        (Some(p), None) => ImportSource::PlaintextDer(crate::keyload::read_masked_key(p)?),
        (None, Some(p)) => ImportSource::WrappedBlob(crate::keyload::read_masked_key(p)?),
        (None, None) => {
            return Err(EngineError::Other(
                "azihsm RSA import requires azihsm.input_key or azihsm.wrapped_key".into(),
            ));
        }
    };
    let (priv_props, pub_props) = import_props(params)?;

    // Unwrap the external key into the HSM, then export its public DER and
    // masked blob (all under one session + unwrapping-key borrow).
    let (imported, pub_der, masked) = data.with_session(|session| {
        data.with_unwrapping_key(session, |unwrap_priv, unwrap_pub| {
            let wrapped = match &source {
                // Wrap the plaintext DER against the HSM's unwrapping public
                // key, exactly as an external party would for wrapped_key. The
                // HSM unwrap parser expects unencrypted PKCS#8, so normalize
                // PKCS#1/SEC1 (or already-PKCS#8) input first, as the provider does.
                ImportSource::PlaintextDer(der) => {
                    let pkcs8 = to_pkcs8_der(der)?;
                    let mut wrap = HsmRsaAesWrapAlgo::new(WRAP_HASH, WRAP_KEK_BYTES);
                    Zeroizing::new(
                        HsmEncrypter::encrypt_vec(&mut wrap, unwrap_pub, &pkcs8)
                            .map_err(|e| EngineError::wrap("RSA-AES wrap input key", e))?,
                    )
                }
                ImportSource::WrappedBlob(blob) => blob.clone(),
            };
            let mut unwrap = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(WRAP_HASH);
            let (imported, _imported_pub) = HsmKeyManager::unwrap_key_pair(
                &mut unwrap,
                unwrap_priv,
                &wrapped,
                priv_props,
                pub_props,
            )
            .map_err(|e| EngineError::wrap("unwrap RSA key into HSM", e))?;
            // On any export failure the key is not yet retained in EngineData
            // and does not delete on drop, so delete it here to avoid leaking it
            // on the HSM until engine teardown.
            let pub_der = match imported.pub_key_der_vec() {
                Ok(v) => v,
                Err(e) => {
                    delete_hsm_key(imported, "imported RSA key");
                    return Err(EngineError::wrap("read imported RSA public DER", e));
                }
            };
            // Zeroizing: the masked blob is the imported private key in its
            // persistent protected form; scrub it once the write/hand-out is done.
            let masked = match imported.masked_key_vec() {
                Ok(v) => Zeroizing::new(v),
                Err(e) => {
                    delete_hsm_key(imported, "imported RSA key");
                    return Err(EngineError::wrap("export imported RSA masked key", e));
                }
            };
            Ok((imported, pub_der, masked))
        })
    })?;

    // Persist the blob before handing the key out, deleting the imported key on
    // a write failure so it does not linger until engine teardown.
    if let Some(path) = &params.masked_key_path
        && let Err(e) = crate::keygen::write_masked_blob(path, &masked)
    {
        delete_hsm_key(imported, "imported RSA key");
        return Err(e);
    }

    // SAFETY: pkey is the keygen out-key OpenSSL passed us; set_pkey_to_bound_rsa
    // consumes `imported` (retained on success, deleted on failure).
    unsafe { crate::rsaload::set_pkey_to_bound_rsa(pkey, engine, data, &pub_der, imported) }
}

/// Export the HSM's unwrapping public key so an external party can wrap a key
/// against it (`key_usage:keyWrapping`). Returns a public-only `EVP_PKEY`.
#[allow(unsafe_code)]
fn export_unwrapping_key(
    data: &EngineData,
    params: &RsaImportParams,
    pkey: *mut ffi::EVP_PKEY,
) -> EngineResult<()> {
    if params.bits != 2048 {
        return Err(EngineError::Other(format!(
            "azihsm.key_usage:keyWrapping requires rsa_keygen_bits=2048 \
             (the HSM unwrapping key is fixed at 2048 bits), got: {}",
            params.bits
        )));
    }
    let der = data.with_session(|session| {
        data.with_unwrapping_key(session, |unwrap_priv, _unwrap_pub| {
            unwrap_priv
                .pub_key_der_vec()
                .map_err(|e| EngineError::wrap("read unwrapping public DER", e))
        })
    })?;
    // SAFETY: pkey is the keygen out-key OpenSSL passed us.
    unsafe { crate::rsaload::set_pkey_to_public_rsa(pkey, &der) }
}

/// Normalize a plaintext private-key DER (traditional PKCS#1/SEC1 or already
/// PKCS#8) to unencrypted PKCS#8 — the form the HSM unwrap parser expects and
/// the provider produces before RSA-AES wrapping.
fn to_pkcs8_der(der: &[u8]) -> EngineResult<Zeroizing<Vec<u8>>> {
    let pkey =
        PKey::private_key_from_der(der).map_err(|e| EngineError::wrap("parse input key DER", e))?;
    pkey.private_key_to_pkcs8()
        .map(Zeroizing::new)
        .map_err(|e| EngineError::wrap("re-encode input key as PKCS#8", e))
}

/// The external key material to import.
enum ImportSource {
    /// A plaintext DER private key (`azihsm.input_key`); the engine wraps it.
    /// Held zeroizing — it is external private-key material.
    PlaintextDer(Zeroizing<Vec<u8>>),
    /// A pre-wrapped blob (`azihsm.wrapped_key`); unwrapped directly.
    WrappedBlob(Zeroizing<Vec<u8>>),
}
