// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM HKDF derivation for masked secrets.
//!
//! The HKDF `EVP_PKEY_METHOD` derive hook lands here for armed contexts (see
//! [`azihsm_ossl_engine_core::hkdf_method`]): the IKM is a masked key blob —
//! typically an ECDH shared secret from [`crate::derive`] — and the output is
//! the masked blob of the derived AES or HMAC key, completing the
//! ECDH → HKDF chain without any secret leaving the HSM.

use std::ffi::c_int;
use std::path::Path;

use azihsm_api::HsmGenericSecretKeyUnmaskAlgo;
use azihsm_api::HsmHashAlgo;
use azihsm_api::HsmHkdfAlgo;
use azihsm_api::HsmKeyClass;
use azihsm_api::HsmKeyCommonProps;
use azihsm_api::HsmKeyKind;
use azihsm_api::HsmKeyManager;
use azihsm_api::HsmKeyPropsBuilder;
use azihsm_ossl_engine_core::engine::Engine;
use azihsm_ossl_engine_core::error::EngineError;
use azihsm_ossl_engine_core::error::EngineResult;
use azihsm_ossl_engine_core::ffi;
use azihsm_ossl_engine_core::hkdf_method::DerivedKeyType;
use azihsm_ossl_engine_core::hkdf_method::HkdfHandler;
use azihsm_ossl_engine_core::hkdf_method::HkdfParams;
use azihsm_ossl_engine_core::hkdf_method::IkmSource;
use zeroize::Zeroizing;

use crate::engine_impl::engine_data_slot;

/// Marker type carrying the engine's HKDF logic (see [`HkdfHandler`]).
pub(crate) struct AzihsmHkdf;

/// Map the `md` digest NID to the HSM hash algorithm.
fn hash_from_nid(nid: c_int) -> EngineResult<HsmHashAlgo> {
    #[allow(clippy::cast_possible_wrap)]
    match nid as u32 {
        ffi::NID_sha256 => Ok(HsmHashAlgo::Sha256),
        ffi::NID_sha384 => Ok(HsmHashAlgo::Sha384),
        ffi::NID_sha512 => Ok(HsmHashAlgo::Sha512),
        _ => Err(EngineError::Other(format!(
            "unsupported HKDF digest (NID {nid}); supported: SHA-256, SHA-384, SHA-512"
        ))),
    }
}

/// Derived-key props per the provider's rules: AES (encrypt/decrypt) for any
/// byte-multiple size; for HMAC the key kind follows the HKDF digest (as the
/// provider derives it from `md`) and the bits must match the digest size.
fn derived_props(
    key_type: DerivedKeyType,
    bits: u32,
    hash: HsmHashAlgo,
) -> EngineResult<azihsm_api::HsmKeyProps> {
    let builder = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .bits(bits);
    let builder = match key_type {
        DerivedKeyType::Aes => builder
            .key_kind(HsmKeyKind::Aes)
            .can_encrypt(true)
            .can_decrypt(true),
        DerivedKeyType::Hmac => {
            let (kind, expected_bits) = match hash {
                HsmHashAlgo::Sha256 => (HsmKeyKind::HmacSha256, 256),
                HsmHashAlgo::Sha384 => (HsmKeyKind::HmacSha384, 384),
                HsmHashAlgo::Sha512 => (HsmKeyKind::HmacSha512, 512),
                _ => {
                    return Err(EngineError::Other(
                        "unsupported HKDF digest for an hmac derived key".into(),
                    ));
                }
            };
            if bits != expected_bits {
                return Err(EngineError::Other(format!(
                    "derived_key_bits for hmac must match the HKDF digest size \
                     ({expected_bits} for this md), got: {bits}"
                )));
            }
            builder.key_kind(kind).can_sign(true).can_verify(true)
        }
    };
    builder
        .build()
        .map_err(|e| EngineError::wrap("build derived key props", e))
}

impl HkdfHandler for AzihsmHkdf {
    fn derive(
        engine: &Engine,
        params: &HkdfParams,
        output_file: Option<&Path>,
    ) -> EngineResult<Option<Zeroizing<Vec<u8>>>> {
        let hash = hash_from_nid(params.md_nid)?;
        let props = derived_props(params.derived_key_type, params.derived_key_bits, hash)?;

        let ikm_blob: Zeroizing<Vec<u8>> = match &params.ikm {
            IkmSource::Bytes(bytes) => Zeroizing::new(bytes.to_vec()),
            IkmSource::File(path) => Zeroizing::new(crate::keyload::read_masked_key(path)?),
        };

        let slot = engine_data_slot()?;
        let data = slot
            .get(engine)
            .ok_or(EngineError::NullParam("engine_data"))?;
        // The IKM file may be the first HSM touch on this ctx (idempotent).
        data.open_hsm_from_env()?;

        // Unmask the IKM, derive, mask the result; both handles are ephemeral
        // — the blobs are the persistent forms.
        let masked = data.with_session(|session| {
            let mut unmask = HsmGenericSecretKeyUnmaskAlgo::default();
            let ikm_key = HsmKeyManager::unmask_key(session, &mut unmask, &ikm_blob)
                .map_err(|e| EngineError::wrap("unmask HKDF IKM", e))?;

            let mut algo = HsmHkdfAlgo::new(hash, params.salt.as_deref(), params.info.as_deref())
                .map_err(|e| EngineError::wrap("build HKDF algo", e))?;
            let derived = HsmKeyManager::derive_key(session, &mut algo, &ikm_key, props);
            crate::context::delete_hsm_key(ikm_key, "HKDF IKM key");

            let derived = derived.map_err(|e| EngineError::wrap("HKDF derive", e))?;
            let masked = derived.masked_key_vec();
            crate::context::delete_hsm_key(derived, "HKDF derived key");
            masked.map_err(|e| EngineError::wrap("export masked derived key", e))
        })?;
        let masked = Zeroizing::new(masked);

        match output_file {
            Some(path) => {
                crate::keygen::write_masked_blob(path, &masked)?;
                Ok(None)
            }
            None => Ok(Some(masked)),
        }
    }
}
