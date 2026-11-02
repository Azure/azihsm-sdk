// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM AES keys for the engine's AES-CBC ciphers (see
//! [`azihsm_ossl_engine_core::cipher_method`]).
//!
//! `AZIHSM_CTRL_SET_KEY_URI` names a masked AES key blob
//! (`azihsm://<path>;type=aes`, e.g. one an HKDF derive wrote). It is unmasked
//! into the HSM for that cipher context (and its copies) and deleted when the
//! last of them is cleaned up or the key is replaced; the blob itself, the
//! persistent form, is never modified. The key must match the cipher's size
//! exactly.

use std::sync::Arc;

use azihsm_api::HsmAesCbcAlgo;
use azihsm_api::HsmAesKey;
use azihsm_api::HsmAesKeyUnmaskAlgo;
use azihsm_api::HsmDecryptOp;
use azihsm_api::HsmEncryptOp;
use azihsm_api::HsmKeyCommonProps;
use azihsm_api::HsmKeyManager;
use azihsm_ossl_engine_core::cipher_method::AES_BLOCK;
use azihsm_ossl_engine_core::cipher_method::AesCbcKey;
use azihsm_ossl_engine_core::cipher_method::AesCbcKeyLoader;
use azihsm_ossl_engine_core::engine::Engine;
use azihsm_ossl_engine_core::error::EngineError;
use azihsm_ossl_engine_core::error::EngineResult;

use crate::context::delete_hsm_key;
use crate::engine_impl::engine_data_slot;
use crate::uri::KeyType;

/// Marker type carrying the engine's AES key loading (see [`AesCbcKeyLoader`]).
pub(crate) struct AzihsmAesCbc;

impl AesCbcKeyLoader for AzihsmAesCbc {
    fn load_key(engine: &Engine, uri: &str, key_bits: u32) -> EngineResult<Arc<dyn AesCbcKey>> {
        let parsed = crate::uri::parse(uri)?;
        if parsed.key_type != KeyType::Aes {
            return Err(EngineError::Other(format!(
                "an AES cipher key URI must have type=aes: {uri}"
            )));
        }
        let slot = engine_data_slot()?;
        let data = slot
            .get(engine)
            .ok_or(EngineError::NullParam("engine_data"))?;
        // First caller may be the cipher (idempotent open).
        data.open_hsm_from_env()?;
        let masked = crate::keyload::read_masked_key(&parsed.masked_key_path)?;
        let key = data.with_session(|session| {
            HsmKeyManager::unmask_key(session, &mut HsmAesKeyUnmaskAlgo::default(), &masked)
                .map_err(|e| EngineError::wrap("AES key unmask", e))
        })?;
        let bits = key.bits();
        if bits != key_bits {
            delete_hsm_key(key, "size-mismatched AES key");
            return Err(EngineError::Other(format!(
                "the AES key is {bits} bits, but the cipher needs {key_bits}"
            )));
        }
        Ok(Arc::new(CbcKey::new(key)))
    }
}

/// An unmasked HSM AES key attached to cipher contexts, deleted from the HSM
/// when dropped.
pub(crate) struct CbcKey(
    /// Always `Some` until dropped (the `Option` lets drop move it out).
    Option<HsmAesKey>,
);

impl CbcKey {
    /// Own `key` (and delete it from the HSM once dropped).
    pub(crate) fn new(key: HsmAesKey) -> Self {
        Self(Some(key))
    }
}

impl Drop for CbcKey {
    fn drop(&mut self) {
        if let Some(key) = self.0.take() {
            delete_hsm_key(key, "cipher AES key");
        }
    }
}

impl AesCbcKey for CbcKey {
    fn cbc(
        &self,
        encrypt: bool,
        iv: &mut [u8; AES_BLOCK],
        input: &[u8],
        output: &mut [u8],
    ) -> EngineResult<()> {
        let key = self.0.as_ref().ok_or(EngineError::NullParam("AES key"))?;
        // Raw CBC: the EVP layer pads and buffers; the algo chains the IV.
        // `input` is at most one device request (HSM_CBC_REQUEST), so the SDK
        // sends it as one, and a retried request restarts from `iv`.
        let mut algo = HsmAesCbcAlgo::with_no_padding(iv.to_vec())
            .map_err(|e| EngineError::wrap("AES-CBC IV", e))?;
        let written = if encrypt {
            HsmEncryptOp::encrypt(&mut algo, key, input, Some(output))
        } else {
            HsmDecryptOp::decrypt(&mut algo, key, input, Some(output))
        }
        .map_err(|e| EngineError::wrap("AES-CBC", e))?;
        if written != input.len() {
            return Err(EngineError::Other(format!(
                "AES-CBC produced {written} of {} bytes",
                input.len()
            )));
        }
        iv.copy_from_slice(algo.iv());
        Ok(())
    }
}
