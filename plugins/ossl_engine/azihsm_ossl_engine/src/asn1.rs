// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Provider-parity serialization policy for HSM-backed EC keys.
//!
//! Mirrors the OpenSSL 3.x provider's encoders (`azihsm_ossl_encoder_ec.c`):
//! a private-key `-text` request on an HSM-backed key prints an informational
//! block instead of key material, and a private-key export request fails with
//! one clear message (the masked blob is the persistent private form) instead
//! of the built-in encoder's raw error trail. Software EC keys are untouched —
//! the toolkit routes them to the ported built-in behavior (see
//! [`azihsm_ossl_engine_core::asn1_method`]).

use std::ffi::c_int;

use azihsm_ossl_engine_core::asn1_method::EcAsn1Handler;
use azihsm_ossl_engine_core::asn1_method::bio_write_all;
use azihsm_ossl_engine_core::error::EngineError;
use azihsm_ossl_engine_core::error::EngineResult;
use azihsm_ossl_engine_core::ffi;

/// Marker type carrying the engine's EC serialization policy.
pub(crate) struct AzihsmEcAsn1;

/// Short display name for the key's curve.
#[allow(unsafe_code)]
fn curve_name(ec: *const ffi::EC_KEY) -> &'static str {
    // SAFETY: ec is a valid EC_KEY; get0 returns a borrowed group (may be NULL).
    let group = unsafe { ffi::EC_KEY_get0_group(ec) };
    if group.is_null() {
        return "unknown";
    }
    // SAFETY: group is valid (checked).
    #[allow(clippy::cast_possible_wrap)]
    match unsafe { ffi::EC_GROUP_get_curve_name(group) } as u32 {
        ffi::NID_X9_62_prime256v1 => "P-256",
        ffi::NID_secp384r1 => "P-384",
        ffi::NID_secp521r1 => "P-521",
        _ => "unknown",
    }
}

impl EcAsn1Handler for AzihsmEcAsn1 {
    /// A key is ours iff the loader/keygen stashed an HSM key in its ex_data.
    #[allow(unsafe_code)]
    fn owns(pkey: *const ffi::EVP_PKEY) -> bool {
        // SAFETY: pkey is a valid EC EVP_PKEY per the ameth contract; get0
        // returns a borrowed EC_KEY (may be NULL).
        let ec = unsafe { ffi::EVP_PKEY_get0_EC_KEY(pkey.cast_mut()) };
        if ec.is_null() {
            return false;
        }
        !crate::keyload::ec_key_hsm_key(ec).is_null()
    }

    /// The `-text` info block, mirroring the provider's text encoder.
    #[allow(unsafe_code)]
    fn print_owned(
        bio: *mut ffi::BIO,
        pkey: *const ffi::EVP_PKEY,
        _indent: c_int,
    ) -> EngineResult<()> {
        // SAFETY: pkey is a valid EC EVP_PKEY; get0 returns a borrowed EC_KEY.
        let ec = unsafe { ffi::EVP_PKEY_get0_EC_KEY(pkey.cast_mut()) };
        if ec.is_null() {
            return Err(EngineError::Other("EVP_PKEY has no EC_KEY".into()));
        }
        let block = format!(
            "\n\
             ==== PrivateKeyInfo (PKCS#8) ====\n\
             engine               : azihsm\n\
             algorithm            : EC\n\
             curve                : {}\n\
             \n\
             NOTE: Full PKCS#8 DER encoding is not implemented.\n\
             \x20     The key remains in the HSM; its persistent private form\n\
             \x20     is the masked key blob (azihsm.masked_key / azihsm:// ids).\n",
            curve_name(ec)
        );
        // SAFETY: bio is the BIO OpenSSL passed to the print callback.
        unsafe { bio_write_all(bio, &block) }
    }

    fn export_refusal() -> &'static str {
        "HSM-backed keys cannot be exported; the masked key blob is the persistent private form"
    }
}
