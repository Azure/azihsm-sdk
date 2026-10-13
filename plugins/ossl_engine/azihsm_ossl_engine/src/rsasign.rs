// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! PKCS#1 v1.5 RSA signing for engine-loaded RSA keys.
//!
//! The engine registers a custom `RSA_METHOD` (see [`rsa_sign_method`]) at bind
//! time via `ENGINE_set_RSA`, so every key the loader/import creates with
//! `RSA_new_method` adopts it. Its `sign` hook recovers the HSM key stashed in
//! the `RSA` ex_data and signs the caller's digest on the HSM: the HSM performs
//! the raw private-key operation and the SDK builds the PKCS#1 v1.5 DigestInfo
//! and padding host-side (see [`azihsm_ossl_engine_core::rsa_method`]).
//! Verification stays in software, using the public key already on the
//! `EVP_PKEY`.
//!
//! Signing reaches this hook only when a **signature digest is set** — the
//! normal `EVP_DigestSign` / `openssl dgst -sign` path, and `EVP_PKEY_sign` /
//! `openssl pkeyutl -sign` when a digest is configured (e.g. `-pkeyopt
//! digest:sha256`). A raw pre-hashed `EVP_PKEY_sign` with no digest set routes
//! (in 1.1.1's `pkey_rsa_sign`) to the copied `rsa_priv_enc` primitive instead,
//! which needs private RSA material the HSM-backed key does not carry; that path
//! is therefore not supported for HSM keys (the HSM exposes no raw private-key
//! primitive to back it).
//!
//! Only HSM-backed keys are signed here. Software RSA keys that merely adopted
//! the engine's method (e.g. because an application made the engine the process
//! default) carry no HSM handle; they are rejected with a clear error rather
//! than signed — software RSA signing through the engine is out of scope for
//! now.
//!
//! RSA-PSS takes a different route (see [`AzihsmRsaPssSign`]): in 1.1.1
//! `pkey_rsa_sign` does PSS padding in software and then calls the raw
//! `rsa_priv_enc` the HSM-backed key cannot back, so PSS cannot ride the
//! `RSA_METHOD` sign slot. Instead the engine's custom RSA `EVP_PKEY_METHOD`
//! overrides `sign`: when the context requests PSS on an HSM-backed key it reads
//! the digest, MGF1 and salt length from the standard signature parameters
//! (`rsa_padding_mode:pss`, `rsa_pss_saltlen`, `rsa_mgf1_md`); the SDK builds the
//! EMSA-PSS block host-side (MGF1 = signing digest) and the HSM performs the raw
//! private-key operation — the same split as the PKCS#1 v1.5 path above.

use std::ffi::c_int;
use std::sync::OnceLock;

use azihsm_api::HsmHashAlgo;
use azihsm_api::HsmRsaPrivateKey;
use azihsm_api::HsmRsaSignAlgo;
use azihsm_api::HsmSigner;
use azihsm_ossl_engine_core::error::EngineError;
use azihsm_ossl_engine_core::error::EngineResult;
use azihsm_ossl_engine_core::ffi;
use azihsm_ossl_engine_core::rsa_method::RsaSignHandler;
use azihsm_ossl_engine_core::rsa_method::new_rsa_sign_method;
use azihsm_ossl_engine_core::rsa_pkey_method::RsaPssSignHandler;
use parking_lot::Mutex;

/// Marker type carrying the engine's RSA sign logic (see [`RsaSignHandler`]).
struct AzihsmRsaSign;

/// Map the digest NID OpenSSL passes to the HSM hash algorithm. Shared by the RSA
/// sign and decrypt (OAEP) paths, so the wording is operation-neutral.
///
/// SHA-256/384/512 only. SHA-1 is deliberately excluded — the SDK marks it
/// cryptographically broken — even though the 3.x provider still maps it for
/// legacy RSA-PKCS#1 signatures; a SHA-1 (or any other) digest is rejected with a
/// clear error.
pub(crate) fn hash_from_nid(nid: c_int) -> EngineResult<HsmHashAlgo> {
    // NIDs are non-negative, so reinterpreting the sign bit is safe.
    #[allow(clippy::cast_sign_loss)]
    match nid as u32 {
        ffi::NID_sha256 => Ok(HsmHashAlgo::Sha256),
        ffi::NID_sha384 => Ok(HsmHashAlgo::Sha384),
        ffi::NID_sha512 => Ok(HsmHashAlgo::Sha512),
        _ => Err(EngineError::Other(format!(
            "unsupported RSA digest (NID {nid}); supported: SHA-256, SHA-384, SHA-512"
        ))),
    }
}

impl RsaSignHandler for AzihsmRsaSign {
    #[allow(unsafe_code)]
    fn sign(rsa: *mut ffi::RSA, md_nid: c_int, m: &[u8]) -> EngineResult<Vec<u8>> {
        let key_ptr = crate::rsaload::rsa_hsm_key(rsa);
        if key_ptr.is_null() {
            return Err(EngineError::Other(
                "no HSM key attached to RSA for signing (software RSA signing through the \
                 engine is not supported)"
                    .into(),
            ));
        }
        // SAFETY: key_ptr points to an HsmRsaPrivateKey owned by EngineData for
        // the engine's lifetime; this callback runs while the key is live.
        let key = unsafe { &*key_ptr };

        // The HSM does the raw private-key operation; the SDK builds the PKCS#1
        // v1.5 DigestInfo and padding around the caller's pre-computed digest.
        let hash = hash_from_nid(md_nid)?;
        let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(hash);
        HsmSigner::sign_vec(&mut algo, key, m).map_err(|e| EngineError::wrap("RSA sign", e))
    }
}

/// Recover the HSM private key stashed in `pkey`'s RSA ex_data, or NULL if
/// `pkey` carries no engine-bound HSM RSA key (a software key).
#[allow(unsafe_code)]
pub(crate) fn hsm_key_from_pkey(pkey: *const ffi::EVP_PKEY) -> *const HsmRsaPrivateKey {
    if pkey.is_null() {
        return std::ptr::null();
    }
    // SAFETY: get0 borrows the RSA from pkey without taking ownership; pkey is
    // valid for the call. A non-RSA or empty pkey yields NULL.
    let rsa = unsafe { ffi::EVP_PKEY_get0_RSA(pkey.cast_mut()) };
    if rsa.is_null() {
        return std::ptr::null();
    }
    crate::rsaload::rsa_hsm_key(rsa)
}

/// Marker type carrying the engine's RSA-PSS sign logic (see
/// [`RsaPssSignHandler`]).
pub(crate) struct AzihsmRsaPssSign;

impl RsaPssSignHandler for AzihsmRsaPssSign {
    fn owns(pkey: *const ffi::EVP_PKEY) -> bool {
        !hsm_key_from_pkey(pkey).is_null()
    }

    #[allow(unsafe_code)]
    fn pss_sign(
        pkey: *const ffi::EVP_PKEY,
        md_nid: c_int,
        salt_len: usize,
        m: &[u8],
    ) -> EngineResult<Vec<u8>> {
        let key_ptr = hsm_key_from_pkey(pkey);
        if key_ptr.is_null() {
            return Err(EngineError::Other(
                "no HSM key attached to RSA for PSS signing".into(),
            ));
        }
        // SAFETY: key_ptr points to an HsmRsaPrivateKey owned by EngineData for
        // the engine's lifetime; this callback runs while the key is live.
        let key = unsafe { &*key_ptr };

        // The SDK builds the EMSA-PSS block (MGF1 = signing digest) over the
        // caller's pre-computed digest; the HSM performs the raw private-key op.
        let hash = hash_from_nid(md_nid)?;
        let mut algo = HsmRsaSignAlgo::with_pss_padding(hash, salt_len);
        HsmSigner::sign_vec(&mut algo, key, m).map_err(|e| EngineError::wrap("RSA-PSS sign", e))
    }
}

/// Process-global RSA sign `RSA_METHOD`, built once and kept for the process
/// lifetime (one method registered on the engine and shared by all loaded keys;
/// never freed, so no libcrypto-held pointer dangles at teardown). Stored as
/// `usize` because a raw pointer is not `Sync`.
pub(crate) fn rsa_sign_method() -> EngineResult<*const ffi::RSA_METHOD> {
    static METHOD: OnceLock<usize> = OnceLock::new();
    static INIT: Mutex<()> = Mutex::new(());

    if let Some(m) = METHOD.get() {
        return Ok(*m as *const ffi::RSA_METHOD);
    }
    // Serialize construction so two concurrent first-loads can't each build a
    // method (only the first is kept; a second would leak).
    let _guard = INIT.lock();
    if let Some(m) = METHOD.get() {
        return Ok(*m as *const ffi::RSA_METHOD);
    }
    let method = new_rsa_sign_method::<AzihsmRsaSign>()?;
    let _ = METHOD.set(method as usize);
    Ok(method)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    // A key with no attached HSM handle (a software RSA key that merely adopted
    // the engine's method) is rejected with a clear error, not signed — software
    // RSA signing through the engine is out of scope.
    #[test]
    #[allow(unsafe_code)]
    fn sign_rejects_key_without_hsm_handle() {
        // SAFETY: a fresh RSA with no ex_data; the sign handler returns before
        // any HSM work, and the RSA is freed below.
        unsafe {
            let rsa = ffi::RSA_new();
            assert!(!rsa.is_null(), "RSA_new");
            let digest = [0u8; 32];
            let err = AzihsmRsaSign::sign(rsa, ffi::NID_sha256 as c_int, &digest)
                .expect_err("a key without an HSM handle must be rejected");
            assert!(
                format!("{err}").contains("no HSM key attached"),
                "unexpected error: {err}"
            );
            ffi::RSA_free(rsa);
        }
    }

    // A software RSA key (an EVP_PKEY with no HSM handle) is not owned by the PSS
    // handler and is rejected rather than signed — the engine's sign path never
    // falls back to a software signature.
    #[test]
    #[allow(unsafe_code)]
    fn pss_owns_false_and_sign_rejects_software_key() {
        // SAFETY: build an EVP_PKEY wrapping a fresh RSA with no HSM ex_data;
        // everything is freed below.
        unsafe {
            let rsa = ffi::RSA_new();
            assert!(!rsa.is_null(), "RSA_new");
            let pkey = ffi::EVP_PKEY_new();
            assert!(!pkey.is_null(), "EVP_PKEY_new");
            assert_eq!(ffi::EVP_PKEY_set1_RSA(pkey, rsa), 1, "set1_RSA");
            assert!(
                !AzihsmRsaPssSign::owns(pkey),
                "a key without an HSM handle must not be owned"
            );
            let digest = [0u8; 32];
            let err = AzihsmRsaPssSign::pss_sign(pkey, ffi::NID_sha256 as c_int, 32, &digest)
                .expect_err("a key without an HSM handle must be rejected");
            assert!(
                format!("{err}").contains("no HSM key attached"),
                "unexpected error: {err}"
            );
            ffi::EVP_PKEY_free(pkey);
            ffi::RSA_free(rsa);
        }
    }

    // SHA-1 is deliberately rejected even though the provider maps it; the
    // supported digests are SHA-256/384/512.
    #[test]
    fn hash_from_nid_rejects_sha1_and_accepts_modern() {
        assert_eq!(
            hash_from_nid(ffi::NID_sha256 as c_int).unwrap(),
            HsmHashAlgo::Sha256
        );
        assert_eq!(
            hash_from_nid(ffi::NID_sha384 as c_int).unwrap(),
            HsmHashAlgo::Sha384
        );
        assert_eq!(
            hash_from_nid(ffi::NID_sha512 as c_int).unwrap(),
            HsmHashAlgo::Sha512
        );
        let err = hash_from_nid(ffi::NID_sha1 as c_int).expect_err("SHA-1 must be rejected");
        assert!(
            format!("{err}").contains("unsupported RSA digest"),
            "unexpected error: {err}"
        );
    }
}
