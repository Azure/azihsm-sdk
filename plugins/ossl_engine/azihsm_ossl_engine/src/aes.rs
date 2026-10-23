// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM AES keys for the engine's AES-CBC ciphers (see
//! [`azihsm_ossl_engine_core::cipher_method`]).
//!
//! `AZIHSM_CTRL_SET_KEY_URI` names a masked AES key blob
//! (`azihsm://<path>;type=aes[;bits=<n>]`, e.g. one [`generate_key`] or an
//! HKDF derive wrote). It is unmasked into the HSM for that cipher context
//! (and its copies) and deleted when the last of them is cleaned up or the key
//! is replaced; the blob itself, the persistent form, is never modified. The
//! key must match the cipher's size exactly.

use std::sync::Arc;

use azihsm_api::HsmAesCbcAlgo;
use azihsm_api::HsmAesGcmKeyGenAlgo;
use azihsm_api::HsmAesKey;
use azihsm_api::HsmAesKeyGenAlgo;
use azihsm_api::HsmAesKeyUnmaskAlgo;
use azihsm_api::HsmAesXtsKeyGenAlgo;
use azihsm_api::HsmDecryptOp;
use azihsm_api::HsmEncryptOp;
use azihsm_api::HsmError;
use azihsm_api::HsmKeyClass;
use azihsm_api::HsmKeyCommonProps;
use azihsm_api::HsmKeyDeleteOp;
use azihsm_api::HsmKeyGenOp;
use azihsm_api::HsmKeyKind;
use azihsm_api::HsmKeyManager;
use azihsm_api::HsmKeyProps;
use azihsm_api::HsmKeyPropsBuilder;
use azihsm_api::HsmSession;
use azihsm_ossl_engine_core::cipher_method::AES_BLOCK;
use azihsm_ossl_engine_core::cipher_method::AesCbcKey;
use azihsm_ossl_engine_core::cipher_method::AesCbcKeyLoader;
use azihsm_ossl_engine_core::engine::Engine;
use azihsm_ossl_engine_core::error::EngineError;
use azihsm_ossl_engine_core::error::EngineResult;
use zeroize::Zeroizing;

use crate::context::delete_hsm_key;
use crate::engine_impl::engine_data_slot;
use crate::uri::AesKind;
use crate::uri::KeyType;

/// Sizes of the HSM's plain AES keys (`type=aes`), in bits.
pub(crate) const AES_KEY_BITS: [u32; 3] = [128, 192, 256];
/// Size of a generated `type=aes` key without `bits=`, as in the provider.
const DEFAULT_AES_KEY_BITS: u32 = 256;
/// The only AES-GCM key size, in bits.
const AES_GCM_KEY_BITS: u32 = 256;
/// The only AES-XTS key size (a pair of AES-256 keys), in bits.
const AES_XTS_KEY_BITS: u32 = 512;

/// Marker type carrying the engine's AES key loading (see [`AesCbcKeyLoader`]).
pub(crate) struct AzihsmAesCbc;

impl AesCbcKeyLoader for AzihsmAesCbc {
    fn load_key(engine: &Engine, uri: &str, key_bits: u32) -> EngineResult<Arc<dyn AesCbcKey>> {
        let parsed = crate::uri::parse(uri)?;
        if parsed.key_type != KeyType::Aes(AesKind::Cbc) {
            return Err(EngineError::Other(format!(
                "an AES cipher key URI must have type=aes: {uri}"
            )));
        }
        if let Some(bits) = parsed.bits
            && bits != key_bits
        {
            return Err(EngineError::Other(format!(
                "the key URI says {bits} bits, but the cipher needs {key_bits}"
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

/// The `GENERATE_KEY` ctrl command: generate the AES key `uri` names
/// (`azihsm://<file>;type=<aes|aes-gcm|aes-xts>[;bits=<n>]`) in the HSM and
/// write its masked blob to the file, replacing any file there. The HSM key is
/// deleted again: the blob is its persistent form.
pub(crate) fn generate_key(engine: &Engine, uri: &str) -> EngineResult<()> {
    let parsed = crate::uri::parse(uri)?;
    let KeyType::Aes(kind) = parsed.key_type else {
        return Err(EngineError::Other(format!(
            "GENERATE_KEY makes AES keys only: {uri}"
        )));
    };
    let props = keygen_props(kind, parsed.bits)?;
    let slot = engine_data_slot()?;
    let data = slot
        .get(engine)
        .ok_or(EngineError::NullParam("engine_data"))?;
    // The command may be the first HSM touch (idempotent open).
    data.open_hsm_from_env()?;
    let masked = data.with_session(|session| match kind {
        AesKind::Cbc => generate_masked(session, HsmAesKeyGenAlgo::default(), props),
        AesKind::Gcm => generate_masked(session, HsmAesGcmKeyGenAlgo::default(), props),
        AesKind::Xts => generate_masked(session, HsmAesXtsKeyGenAlgo::default(), props),
    })?;
    crate::keygen::write_masked_blob(&parsed.masked_key_path, &masked)
}

/// Props of a new `kind` key of `bits` bits: 256 by default for `type=aes`,
/// the only size for the other kinds.
fn keygen_props(kind: AesKind, bits: Option<u32>) -> EngineResult<HsmKeyProps> {
    let (key_kind, sizes, default): (HsmKeyKind, &[u32], u32) = match kind {
        AesKind::Cbc => (HsmKeyKind::Aes, &AES_KEY_BITS, DEFAULT_AES_KEY_BITS),
        AesKind::Gcm => (HsmKeyKind::AesGcm, &[AES_GCM_KEY_BITS], AES_GCM_KEY_BITS),
        AesKind::Xts => (HsmKeyKind::AesXts, &[AES_XTS_KEY_BITS], AES_XTS_KEY_BITS),
    };
    let bits = bits.unwrap_or(default);
    if !sizes.contains(&bits) {
        return Err(EngineError::Other(format!(
            "unsupported key size {bits} for this AES key type; supported: {sizes:?}"
        )));
    }
    HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(key_kind)
        .bits(bits)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .map_err(|e| EngineError::wrap("build AES key props", e))
}

/// Generate a key with `algo` and `props` and return its masked blob. The key
/// is deleted from the HSM again, also when the export fails.
fn generate_masked<A>(
    session: &HsmSession,
    mut algo: A,
    props: HsmKeyProps,
) -> EngineResult<Zeroizing<Vec<u8>>>
where
    A: HsmKeyGenOp<Session = HsmSession, Error = HsmError>,
    A::Key: HsmKeyCommonProps + HsmKeyDeleteOp,
{
    let key = HsmKeyManager::generate_key(session, &mut algo, props)
        .map_err(|e| EngineError::wrap("generate AES key", e))?;
    let masked = key.masked_key_vec();
    delete_hsm_key(key, "generated AES key");
    masked
        .map(Zeroizing::new)
        .map_err(|e| EngineError::wrap("export masked AES key", e))
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
