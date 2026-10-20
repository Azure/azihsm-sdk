// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RSA decryption (OAEP and PKCS#1 v1.5) for engine-loaded RSA keys.
//!
//! Decryption takes the same route as RSA-PSS (see [`crate::rsasign`]): in 1.1.1
//! `pkey_rsa_decrypt` does the raw private-key operation in `rsa_priv_dec` (which
//! the HSM-backed key cannot back) and strips the padding in software, so it
//! cannot ride the `RSA_METHOD` slot. Instead the engine's custom RSA
//! `EVP_PKEY_METHOD` overrides `decrypt`: for an OAEP/PKCS#1 request on an
//! HSM-backed key it reads the padding parameters from the ctx and decrypts on
//! the HSM, where the SDK ([`HsmRsaEncryptAlgo`]) removes the padding. A request
//! on a key the engine does not own is delegated to the built-in software decrypt
//! by the core method — required so the SDK's own internal RSA decrypt during key
//! unwrap still works when the engine is the process default.
//!
//! Encryption is a public-key operation and is left on the inherited built-in
//! slot: a loaded key carries the public modulus, so software RSA public-key
//! encryption already produces the right ciphertext.

use azihsm_api::HsmDecrypter;
use azihsm_api::HsmRsaEncryptAlgo;
use azihsm_ossl_engine_core::error::EngineError;
use azihsm_ossl_engine_core::error::EngineResult;
use azihsm_ossl_engine_core::ffi;
use azihsm_ossl_engine_core::rsa_pkey_method::RsaDecryptHandler;
use azihsm_ossl_engine_core::rsa_pkey_method::RsaDecryptPadding;

use crate::rsasign::hash_from_nid;
use crate::rsasign::hsm_key_from_pkey;

/// Marker type carrying the engine's RSA decryption logic (see
/// [`RsaDecryptHandler`]).
pub(crate) struct AzihsmRsaDecrypt;

impl RsaDecryptHandler for AzihsmRsaDecrypt {
    fn owns(pkey: *const ffi::EVP_PKEY) -> bool {
        !hsm_key_from_pkey(pkey).is_null()
    }

    #[allow(unsafe_code)]
    fn decrypt(
        pkey: *const ffi::EVP_PKEY,
        padding: &RsaDecryptPadding,
        ciphertext: &[u8],
    ) -> EngineResult<Vec<u8>> {
        let key_ptr = hsm_key_from_pkey(pkey);
        if key_ptr.is_null() {
            return Err(EngineError::Other(
                "no HSM key attached to RSA for decryption".into(),
            ));
        }
        // SAFETY: key_ptr points to an HsmRsaPrivateKey owned by EngineData for
        // the engine's lifetime; this callback runs while the key is live.
        let key = unsafe { &*key_ptr };

        // The HSM performs the raw private-key operation; the SDK removes the
        // OAEP/PKCS#1 v1.5 padding (OAEP MGF1 = the OAEP digest).
        let mut algo = match padding {
            RsaDecryptPadding::Pkcs1 => HsmRsaEncryptAlgo::with_pkcs1_padding(),
            RsaDecryptPadding::Oaep { md_nid, label } => {
                let hash = hash_from_nid(*md_nid)?;
                let label = if label.is_empty() {
                    None
                } else {
                    Some(label.as_slice())
                };
                HsmRsaEncryptAlgo::with_oaep_padding(hash, label)
            }
        };
        HsmDecrypter::decrypt_vec(&mut algo, key, ciphertext)
            .map_err(|e| EngineError::wrap("RSA decrypt", e))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    // A software RSA key (an EVP_PKEY with no HSM handle) is not owned by the
    // decrypt handler; the core method delegates such keys to the built-in
    // decrypt, and the handler's own guard (exercised directly here) is a
    // defensive backstop that rejects a null HSM handle.
    #[test]
    #[allow(unsafe_code)]
    fn decrypt_rejects_key_without_hsm_handle() {
        // SAFETY: build an EVP_PKEY wrapping a fresh RSA with no HSM ex_data;
        // everything is freed below.
        unsafe {
            let rsa = ffi::RSA_new();
            assert!(!rsa.is_null(), "RSA_new");
            let pkey = ffi::EVP_PKEY_new();
            assert!(!pkey.is_null(), "EVP_PKEY_new");
            assert_eq!(ffi::EVP_PKEY_set1_RSA(pkey, rsa), 1, "set1_RSA");
            assert!(
                !AzihsmRsaDecrypt::owns(pkey),
                "a key without an HSM handle must not be owned"
            );
            let err = AzihsmRsaDecrypt::decrypt(pkey, &RsaDecryptPadding::Pkcs1, &[0u8; 8])
                .expect_err("a key without an HSM handle must be rejected");
            assert!(
                format!("{err}").contains("no HSM key attached"),
                "unexpected error: {err}"
            );
            ffi::EVP_PKEY_free(pkey);
            ffi::RSA_free(rsa);
        }
    }
}
