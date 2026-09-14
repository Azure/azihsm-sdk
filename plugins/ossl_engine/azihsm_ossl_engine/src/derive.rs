// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM ECDH derivation for engine-backed EC keys.
//!
//! The EC `EVP_PKEY_METHOD` derive hook lands here when the local key is
//! HSM-backed (loaded via `azihsm://` or generated with
//! `azihsm.key_usage:keyAgreement`). The shared secret never leaves the HSM:
//! like the 3.x provider's keyexch, the output is the masked blob of the
//! derived shared-secret key — into the caller's buffer, or to the
//! `output_file` path when that option was set. The peer is an ordinary
//! software public key. Software local keys never reach this module (the
//! toolkit delegates them to the built-in derive).

use std::ffi::c_uchar;
use std::ffi::c_void;
use std::path::Path;
use std::ptr::null_mut;

use azihsm_api::EcdhAlgo;
use azihsm_api::HsmKeyClass;
use azihsm_api::HsmKeyCommonProps;
use azihsm_api::HsmKeyKind;
use azihsm_api::HsmKeyManager;
use azihsm_api::HsmKeyPropsBuilder;
use azihsm_ossl_engine_core::engine::Engine;
use azihsm_ossl_engine_core::error::EngineError;
use azihsm_ossl_engine_core::error::EngineResult;
use azihsm_ossl_engine_core::ffi;
use azihsm_ossl_engine_core::pkey_method::EcDeriveHandler;
use zeroize::Zeroizing;

use crate::engine_impl::engine_data_slot;

/// Marker type carrying the engine's ECDH derive logic (see
/// [`EcDeriveHandler`]).
pub(crate) struct AzihsmEcDerive;

/// DER-encode `pkey`'s public half (SPKI).
#[allow(unsafe_code)]
fn pubkey_der(pkey: *const ffi::EVP_PKEY) -> EngineResult<Vec<u8>> {
    // SAFETY: i2d allocates via OPENSSL_malloc when the out-pointer starts
    // NULL; the buffer is copied and freed here.
    unsafe {
        let mut buf: *mut c_uchar = null_mut();
        let len = ffi::i2d_PUBKEY(pkey.cast_mut(), &mut buf);
        let Ok(len) = usize::try_from(len) else {
            return Err(EngineError::Other("i2d_PUBKEY failed".into()));
        };
        if len == 0 || buf.is_null() {
            return Err(EngineError::Other("i2d_PUBKEY failed".into()));
        }
        let der = std::slice::from_raw_parts(buf, len).to_vec();
        ffi::CRYPTO_free(buf.cast::<c_void>(), c"".as_ptr(), 0);
        Ok(der)
    }
}

impl EcDeriveHandler for AzihsmEcDerive {
    /// A key is ours iff the loader/keygen stashed an HSM key in its ex_data.
    #[allow(unsafe_code)]
    fn owns(pkey: *const ffi::EVP_PKEY) -> bool {
        // SAFETY: pkey is a valid EVP_PKEY; get0 returns a borrowed EC_KEY or
        // NULL (non-EC keys).
        let ec = unsafe { ffi::EVP_PKEY_get0_EC_KEY(pkey.cast_mut()) };
        if ec.is_null() {
            return false;
        }
        !crate::keyload::ec_key_hsm_key(ec).is_null()
    }

    #[allow(unsafe_code)]
    fn derive(
        engine: &Engine,
        pkey: *const ffi::EVP_PKEY,
        peer: *const ffi::EVP_PKEY,
        output_file: Option<&Path>,
    ) -> EngineResult<Option<Zeroizing<Vec<u8>>>> {
        // SAFETY: pkey is a valid EC EVP_PKEY (owns() checked it).
        let ec = unsafe { ffi::EVP_PKEY_get0_EC_KEY(pkey.cast_mut()) };
        let key_ptr = crate::keyload::ec_key_hsm_key(ec);
        if key_ptr.is_null() {
            return Err(EngineError::Other("no HSM key attached for derive".into()));
        }
        // SAFETY: key_ptr is owned by EngineData and alive for the engine's
        // lifetime.
        let hsm_key = unsafe { &*key_ptr };

        let curve = hsm_key
            .ecc_curve()
            .ok_or(EngineError::Other("HSM key has no curve".into()))?;
        let bits = u32::try_from(curve.key_size_bits())
            .map_err(|_| EngineError::Other("curve size out of range".into()))?;

        let peer_der = pubkey_der(peer)?;

        let slot = engine_data_slot()?;
        let data = slot
            .get(engine)
            .ok_or(EngineError::NullParam("engine_data"))?;

        // Derived shared secret: same props as the provider's keyexch.
        let masked = data.with_session(|session| {
            let props = HsmKeyPropsBuilder::default()
                .class(HsmKeyClass::Secret)
                .key_kind(HsmKeyKind::SharedSecret)
                .can_derive(true)
                .bits(bits)
                .build()
                .map_err(|e| EngineError::wrap("build shared secret props", e))?;
            let mut algo = EcdhAlgo::new(&peer_der);
            let derived = HsmKeyManager::derive_key(session, &mut algo, hsm_key, props)
                .map_err(|e| EngineError::wrap("ECDH derive", e))?;
            let masked = derived.masked_key_vec();
            // Ephemeral handle — the blob is the persistent form; deletion is
            // best-effort cleanup (HSM keys are not deleted by their drop).
            crate::context::delete_hsm_key(derived, "derived shared secret");
            masked.map_err(|e| EngineError::wrap("export masked shared secret", e))
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
