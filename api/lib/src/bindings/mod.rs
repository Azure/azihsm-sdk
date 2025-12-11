// Copyright (C) Microsoft Corporation. All rights reserved.

mod crypto_digest;
mod crypto_enc_dec;
mod crypto_sign_verify;
mod ffi_types;
mod handle_table;
mod key_mgmt;
mod key_props;
mod partition;
mod session;
mod str;
mod utils;

use std::panic::UnwindSafe;

pub(crate) use handle_table::*;
use lazy_static::lazy_static;
pub use partition::*;
pub use str::*;
pub(crate) use utils::*;

use crate::bindings::ffi_types::AzihsmAlgoAesCbcParams;
use crate::bindings::ffi_types::AzihsmAlgoAesXtsParams;
use crate::bindings::ffi_types::AzihsmAlgoHkdfParams;
use crate::bindings::ffi_types::AzihsmAlgoRsaAesKeyWrapParams;
use crate::bindings::ffi_types::AzihsmAlgoRsaPkcsOaepParams;
use crate::bindings::ffi_types::AzihsmAlgoRsaPkcsPssParams;
use crate::types::EcCurve;

/// Handle type
pub type AzihsmHandle = u32;

/// Error type
pub type AzihsmError = i32;

/// Success error code
pub const AZIHSM_ERROR_SUCCESS: AzihsmError = 0;

/// Panic error code
pub const AZIHSM_ERROR_PANIC: AzihsmError = -1;

/// Invalid argument error code
pub const AZIHSM_ERROR_INVALID_ARGUMENT: AzihsmError = -2;

/// Invalid handle error code
pub const AZIHSM_ERROR_INVALID_HANDLE: AzihsmError = -3;

/// Index out of range error code
pub const AZIHSM_ERROR_INDEX_OUT_OF_RANGE: AzihsmError = -4;

/// Insufficient buffer error code
pub const AZIHSM_ERROR_INSUFFICIENT_BUFFER: AzihsmError = -5;

/// Invalid api version error code
pub const AZIHSM_ERROR_INVALID_API_REV: AzihsmError = -6;

/// Invalid credentials error code
pub const AZIHSM_INVALID_CREDENTIALS: AzihsmError = -7;

/// Session open error code
pub const AZIHSM_OPEN_SESSION_FAILED: AzihsmError = -8;

/// Session close error code
pub const AZIHSM_CLOSE_SESSION_FAILED: AzihsmError = -9;

/// Session already closed error code
pub const AZIHSM_SESSION_ALREADY_CLOSED: AzihsmError = -10;

/// Initialize BK3 failed error code
pub const AZIHSM_INIT_BK3_FAILED: AzihsmError = -11;

/// Get establish credential encryption key failed error code
pub const AZIHSM_GET_ESTABLISH_CREDENTIAL_ENCRYPTION_KEY_FAILED: AzihsmError = -12;

/// Get session encryption key failed error code
pub const AZIHSM_GET_SESSION_ENCRYPTION_KEY_FAILED: AzihsmError = -13;

/// Open partition failed error code
pub const AZIHSM_OPEN_PARTITION_FAILED: AzihsmError = -14;

/// Get api revision failed error code
pub const AZIHSM_GET_API_REVISION_FAILED: AzihsmError = -15;

/// Get partition info failed error code
pub const AZIHSM_GET_PARTITION_INFO_FAILED: AzihsmError = -16;

/// Key property not settable error code
pub const AZIHSM_KEY_PROPERTY_NOT_SETTABLE: AzihsmError = -17;

/// Algorithm not supported error code
pub const AZIHSM_ALGORITHM_NOT_SUPPORTED: AzihsmError = -18;

/// Illegal key property error code
pub const AZIHSM_ILLEGAL_KEY_PROPERTY: AzihsmError = -19;

/// Key property not present error code
pub const AZIHSM_KEY_PROPERTY_NOT_PRESENT: AzihsmError = -20;

/// Key already exists error code
pub const AZIHSM_KEY_ALREADY_EXISTS: AzihsmError = -21;

/// Operation not supported error code
pub const AZIHSM_OPERATION_NOT_SUPPORTED: AzihsmError = -22;

/// Illegal property operation error code
pub const AZIHSM_ILLEGAL_KEY_PROPERTY_OPERATION: AzihsmError = -23;

/// AES key generation failed error code
pub const AZIHSM_AES_KEYGEN_FAILED: AzihsmError = -30;

/// Delete key failed error code
pub const AZIHSM_DELETE_KEY_FAILED: AzihsmError = -31;

/// AES encrypt failed error code
pub const AZIHSM_AES_ENCRYPT_FAILED: AzihsmError = -32;

/// AES decrypt failed error code
pub const AZIHSM_AES_DECRYPT_FAILED: AzihsmError = -33;

/// AES invalid key size error code
pub const AZIHSM_AES_INVALID_KEY_SIZE: AzihsmError = -34;

/// ECC key generation failed error code
pub const AZIHSM_ECC_KEYGEN_FAILED: AzihsmError = -34;

/// Key not initialized error code
pub const AZIHSM_KEY_NOT_INITIALIZED: AzihsmError = -35;

/// ECC sign failed error code
pub const AZIHSM_ECC_SIGN_FAILED: AzihsmError = -36;

/// ECC verify failed error code
pub const AZIHSM_ECC_VERIFY_FAILED: AzihsmError = -37;

/// Unsupported key size error code
pub const AZIHSM_UNSUPPORTED_KEY_SIZE: AzihsmError = -38;

/// RSA key generation failed error code
pub const AZIHSM_RSA_KEYGEN_FAILED: AzihsmError = -40;

/// RSA invalid padding error code
pub const AZIHSM_RSA_INVALID_PADDING: AzihsmError = -41;

/// RSA invalid key size error code
pub const AZIHSM_RSA_INVALID_KEY_SIZE: AzihsmError = -42;

/// RSA unsupported hash algorithm error code
pub const AZIHSM_RSA_UNSUPPORTED_HASH_ALGORITHM: AzihsmError = -43;

/// RSA Unwrap failed error code
pub const AZIHSM_RSA_UNWRAP_FAILED: AzihsmError = -44;

/// RSA unwrap keykind not supported
pub const AZIHSM_KEY_KIND_NOT_SUPPORTED: AzihsmError = -45;

/// RSA sign failed error code
pub const AZIHSM_RSA_SIGN_FAILED: AzihsmError = -46;

/// RSA verify failed error code
pub const AZIHSM_RSA_VERIFY_FAILED: AzihsmError = -47;

/// RSA verify internal failed error code
pub const AZIHSM_RSA_VERIFY_INTERNAL_ERROR: AzihsmError = -48;

/// RSA Invalid pub Key
pub const AZIHSM_RSA_INVALID_PUB_KEY: AzihsmError = -49;

/// RSA Invalid MGF1 Hash Algorithm
pub const AZIHSM_ERROR_INVALID_HASH_ALGO: AzihsmError = -50;

/// RSA unwrap invalid key id error code
pub const AZIHSM_RSA_UNWRAP_INVALID_KEY_ID: AzihsmError = -51;

/// RSA crypto operation failed error code  
pub const AZIHSM_RSA_CRYPTO_ERROR: AzihsmError = -52;

/// ECDH derive failed error code
pub const AZIHSM_ECDH_DERIVE_FAILED: AzihsmError = -53;

/// HKDF derive failed error code
pub const AZIHSM_HKDF_DERIVE_FAILED: AzihsmError = -54;

/// HMAC sign failed error code
pub const AZIHSM_HMAC_SIGN_FAILED: AzihsmError = -55;

/// HMAC verify failed error code
pub const AZIHSM_HMAC_VERIFY_FAILED: AzihsmError = -56;

/// Unsupported data unit length error code
pub const AZIHSM_AES_UNSUPPORTED_DATA_UNIT_LENGTH: AzihsmError = -57;

/// Message too large error code
pub const AZIHSM_ERROR_MSG_TOO_LARGE: AzihsmError = -99;

/// Internal error code
pub const AZIHSM_INTERNAL_ERROR: AzihsmError = -100;

lazy_static! {
    /// Handle table
    static ref HANDLE_TABLE: handle_table::HandleTable = handle_table::HandleTable::default();
}

pub(crate) fn abi_boundary<F: FnOnce() -> Result<(), AzihsmError> + UnwindSafe>(
    f: F,
) -> AzihsmError {
    match std::panic::catch_unwind(f) {
        Ok(hr) => match hr {
            Ok(_) => AZIHSM_ERROR_SUCCESS,
            Err(err) => err,
        },
        Err(_) => AZIHSM_ERROR_PANIC,
    }
}

#[no_mangle]
#[doc(hidden)]
#[allow(unsafe_code)]
pub extern "C" fn __azihsm_internal_for_bindgen(
    _: AzihsmAlgoAesCbcParams,
    _: AzihsmAlgoAesXtsParams,
    _: AzihsmAlgoRsaAesKeyWrapParams,
    _: AzihsmAlgoRsaPkcsOaepParams,
    _: AzihsmAlgoRsaPkcsPssParams,
    _: AzihsmAlgoHkdfParams,
    _: EcCurve,
) {
    // This function is a placeholder for internal use by bindgen.
}
