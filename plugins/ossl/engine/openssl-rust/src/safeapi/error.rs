// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_int;
use std::ffi::CString;
use std::ffi::FromBytesUntilNulError;
use std::ffi::NulError;
use std::fmt::Debug;
use std::panic::catch_unwind;
use std::panic::UnwindSafe;
use std::process::abort;

use thiserror;

#[cfg(feature = "openssl_111")]
use crate::ERR_add_error_data;
#[cfg(feature = "openssl_3")]
use crate::ERR_new;
#[cfg(feature = "openssl_111")]
use crate::ERR_put_error;
#[cfg(feature = "openssl_3")]
use crate::ERR_set_debug;
#[cfg(feature = "openssl_3")]
use crate::ERR_set_error;
use crate::ERR_LIB_ENGINE;
use crate::ERR_R_INTERNAL_ERROR;
use crate::ERR_R_MALLOC_FAILURE;
use crate::ERR_R_OPERATION_FAIL;
use crate::ERR_R_PASSED_INVALID_ARGUMENT;
use crate::ERR_R_PASSED_NULL_PARAMETER;
#[cfg(feature = "openssl_3")]
use crate::ERR_R_UNSUPPORTED;

pub fn openssl_do_log(
    error_code: c_int,
    file: &str,
    line: u32,
    log_string: &str,
) -> OpenSSLResult<()> {
    let file_cstring = CString::new(file).map_err(OpenSSLError::CStringNulError)?;
    let log_cstring = CString::new(log_string).map_err(OpenSSLError::CStringNulError)?;

    #[cfg(feature = "openssl_111")]
    unsafe {
        ERR_put_error(
            ERR_LIB_ENGINE as c_int,
            -1,
            error_code as c_int,
            file_cstring.as_ptr(),
            line as c_int,
        );
        ERR_add_error_data(1, log_cstring.as_ptr());
    }

    #[cfg(feature = "openssl_3")]
    unsafe {
        ERR_new();
        ERR_set_debug(file_cstring.as_ptr(), line as c_int, c"".as_ptr());
        ERR_set_error(
            ERR_LIB_ENGINE as c_int,
            error_code as c_int,
            c"%s".as_ptr(),
            log_cstring.as_ptr(),
        );
    }

    Ok(())
}

pub const fn level_to_string(level: tracing::Level) -> &'static str {
    match level {
        ::tracing::Level::TRACE => "TRACE",
        ::tracing::Level::DEBUG => "DEBUG",
        ::tracing::Level::INFO => "INFO",
        ::tracing::Level::WARN => "WARN",
        ::tracing::Level::ERROR => "ERROR",
    }
}

#[macro_export]
macro_rules! openssl_log {
    ($error:expr, $level:expr, $($arg:tt)*) => {
        let file = file!();
        let line = line!();
        let error_code = ::std::primitive::i32::from($error);
        let level = $crate::safeapi::error::level_to_string($level);
        let log_string = format!("[{level}] {}: {}", $error, format!($($arg)*));
        $crate::safeapi::error::openssl_do_log(error_code, file, line, &log_string).ok();

        match $level {
            ::tracing::Level::TRACE => tracing::trace!("{file}:{line}: {log_string}"),
            ::tracing::Level::DEBUG => tracing::debug!("{file}:{line}: {log_string}"),
            ::tracing::Level::INFO => tracing::info!("{file}:{line}: {log_string}"),
            ::tracing::Level::WARN => tracing::warn!("{file}:{line}: {log_string}"),
            ::tracing::Level::ERROR => tracing::error!("{file}:{line}: {log_string}"),
        }
    };
}

#[macro_export]
macro_rules! openssl_log_noerror {
    ($level:expr, $($arg:tt)*) => {
        let file = file!();
        let line = line!();
        let level = $crate::safeapi::error::level_to_string($level);
        let log_string = format!("[{level}] {}", format!($($arg)*));
        $crate::safeapi::error::openssl_do_log($crate::ERR_R_ENGINE_LIB, file, line, &log_string).ok();

        match $level {
            ::tracing::Level::TRACE => tracing::trace!("{file}:{line}: {log_string}"),
            ::tracing::Level::DEBUG => tracing::debug!("{file}:{line}: {log_string}"),
            ::tracing::Level::INFO => tracing::info!("{file}:{line}: {log_string}"),
            ::tracing::Level::WARN => tracing::warn!("{file}:{line}: {log_string}"),
            ::tracing::Level::ERROR => tracing::error!("{file}:{line}: {log_string}"),
        }
    };
}

/// OpenSSL error type
#[derive(Debug, thiserror::Error, Clone)]
pub enum OpenSSLError {
    /// Generic OpenSSL error type
    #[error("OpenSSL Error: {0}")]
    OpenSSLError(i32),

    /// No Nul terminator found in CString
    #[error("No null terminator found in string")]
    CStringNoNulError(#[from] FromBytesUntilNulError),

    /// Nul terminator found in CString
    #[error("Null terminator found in string")]
    CStringNulError(#[from] NulError),

    /// Allocation failed
    #[error("Allocating data structure failed")]
    AllocationFailed,

    /// ID does not match
    #[error("ID mismatch")]
    IdMismatch,

    /// Could not get engine ID
    #[error("Could not get engine ID")]
    GetIdError,

    /// Engine methods already unregistered
    #[error("Engine methods already unregistered")]
    AlreadyUnregistered,

    /// Could not set engine ID
    #[error("Could not set engine ID")]
    EngineSetIdError,

    /// Could not set engine name
    #[error("Could not set engine name")]
    EngineSetNameError,

    /// Could not set ciphers
    #[error("Could not set cipher methods")]
    EngineSetCiphersError,

    /// Could not set EC methods
    #[error("Could not set EC methods")]
    EngineSetEcError,

    /// Could not set RSA methods
    #[error("Could not set RSA methods")]
    EngineSetRsaError,

    /// Could not set pkey methods
    #[error("Could not set engine PKey methods")]
    EngineSetPKeyMethsError,

    /// Could not set default EC methods
    #[error("Could not set default EC methods")]
    EngineSetDefaultEcError,

    /// Could not set engine destroy callback
    #[error("Could not set engine destroy callback")]
    EngineSetDestroyError,

    /// Could not set engine ctrl function callback
    #[error("Could not set engine ctrl function callback")]
    EngineSetCtrlFunctionError,

    /// Could not set engine control definitions callback
    #[error("Could not set engine ctrl defns callback")]
    EngineSetCtrlDefnsError,

    /// Key Data index error
    #[error("Key Data index error")]
    KeyDataIndexError,

    /// Engine Data index error
    #[error("Engine Data index error")]
    EngineDataIndexError,

    /// Unsupported key type
    #[error("Unsupported key type")]
    UnsupportedKeyType,

    /// Error generating key
    #[error("Could not generate key")]
    KeyGenerationError,

    /// Invalid key type
    #[error("Invalid key type")]
    InvalidKeyType,

    /// Invalid key data
    #[error("Invalid key data")]
    InvalidKeyData,

    /// Invalid key
    #[error("Invalid key")]
    InvalidKey,

    /// Error attesting key
    #[error("Could not attest key")]
    AttestKeyError,

    /// Invalid report data in Key Attestation
    #[error("Invalid report data")]
    AttestKeyInvalidReport,

    /// Error generating signature
    #[error("Invalid length of signature: {0}")]
    InvalidSignatureLength(usize),

    /// SSL engine object is null
    #[error("SSL engine object is null")]
    EngineNulError,

    /// Engine Init failed
    #[error("Engine Init failed: {0}")]
    EngineInitError(String),

    /// Engine Ctrl type not supported
    #[error("Engine ctrl type not supported: {0}")]
    EngineCtrlNotSupported(u32),

    /// Invalid engine logging level
    #[error("Could not open log file: {0}")]
    LogFileError(String),

    /// Wrapped key is invalid
    #[error("Wrapped key is invalid")]
    InvalidWrappedKey,

    /// Invalid key usage
    #[error("Invalid key usage")]
    InvalidKeyUsage,

    /// Hash not supported
    #[error("Hash type not supported")]
    HashNotSupported,

    /// MD pointer is null
    #[error("MD pointer is null")]
    MdPointerNull,

    /// Padding type not supported
    #[error("Padding type not supported")]
    PaddingNotSupported,

    /// Salt length not supported
    #[error("Salt length not supported")]
    SaltLengthNotSupported,

    /// No Ciphers available
    #[error("No ciphers available")]
    NoCiphersAvailable,

    /// Cipher not supported
    #[error("Cipher with nid {0} not supported")]
    CipherNotSupported(i32),

    /// Cipher Method not initialized
    #[error("Cipher Method not initialized")]
    CipherNotInitialized,

    /// Cipher Operation not supported
    #[error("Cipher Operation not supported")]
    CipherUnsupportedOperation,

    /// Cipher Ctx not initialized
    #[error("Cipher Ctx not initialized")]
    CipherCtxNotInitialized,

    /// Could not set cipher data
    #[error("Could not get cipher ctx data")]
    CipherCtxGetDataError,

    /// Error retrieving ciphers
    #[error("Could not retrieve list of ciphers")]
    CipherMethodRetrievalError,

    /// Error initializing cipher
    #[error("Could not init cipher ctx")]
    CipherCtxInitFailed,

    /// Error setting cipher IV length method
    #[error("Could not set cipher method IV length")]
    CipherMethSetIvLengthFailed,

    /// Error setting cipher flags method
    #[error("Could not set cipher method flags")]
    CipherMethSetFlagsFailed,

    /// Error setting cipher impl ctx size method
    #[error("Could not set cipher method impl ctx size")]
    CipherMethSetImplCtxSizeFailed,

    /// Error setting cipher init method
    #[error("Could not set cipher method init")]
    CipherMethSetInitFailed,

    /// Error setting cipher ctrl method
    #[error("Could not set cipher method ctrl")]
    CipherMethSetCtrlFailed,

    /// Error setting cipher do cipher method
    #[error("Could not set cipher method do_cipher")]
    CipherMethSetDoCipherFailed,

    /// Error setting cipher do cipher method
    #[error("Could not set cipher method cleanup")]
    CipherMethSetCleanupFailed,

    /// Incorrect Param
    #[error("Incorrect {0}, expected {1}, got {2}")]
    IncorrectParam(String, String, String),

    /// Unexpected null parameter
    #[error("Incorrect null parameter {0}, expected nonnull")]
    NullParam(String),

    /// HSM incorrect parameter error
    #[error("Incorrect parameter to HSM call: {0}")]
    IncorrectHsmParam(String),

    /// No PKey methods available
    #[error("No PKey methods available")]
    NoPKeyMethodsAvailable,

    /// PKey Method not initialized
    #[error("PKey Method not initialized")]
    PKeyMethodNotInitialized,

    /// PKey method not supported
    #[error("PKey method with nid {0} not supported")]
    PKeyNotSupported(u32),

    /// Error retrieving pkey methods
    #[error("Could not retrieve list of pkey methods")]
    PKeyMethodRetrievalError,

    /// Signing failed with error
    #[error("Signing failed")]
    SignFailed,

    /// Signature verification failed
    #[error("Signature verififcation failed")]
    VerifyFailed,

    /// Decryption failed
    #[error("Encryption failed")]
    DecryptionFailed,

    /// Encryption failed
    #[error("Encryption failed")]
    EncryptionFailed,

    /// Digest init failed
    #[error("Digest init failed")]
    DigestInitError,

    /// Digest update failed
    #[error("Digest update failed")]
    DigestUpdateError,

    /// Digest finalize failed
    #[error("Digest finalize failed")]
    DigestFinalError,

    /// Engine no app session error
    #[error("No app session")]
    EngineNoAppSession,

    /// Bignum conversion error
    #[error("Bignum conversion error")]
    BigNumConversionFailure,

    /// Invalid Key Handle
    #[error("Invalid Key Handle {0}")]
    InvalidKeyHandle(usize),

    /// Memory BIO data error
    #[error("Error getting BIO memory data")]
    BioMemDataError,

    /// Not implemented
    #[error("Not implemented")]
    NotImplemented,

    /// Missing input Key
    #[error("Missing {0} input Key")]
    MissingKey(String),

    /// Internal OpenSSL error
    #[error("Internal OpenSSL error: {0}")]
    InternalError(String),

    /// HKDF Missing Digest
    #[error("HKDF Missing Digest Type")]
    HkdfMissingDigest,

    /// HKDF Unsupported Digest type
    #[error("HKDF Unsupported Digest type")]
    HkdfUnsupportedDigest,

    /// HKDF Unsupported Target Key Type
    #[error("HKDF Unsupported Target Key Type {0}")]
    HkdfUnsupportedKeyType(i32),

    /// HKDF Unsupported Mode in derive
    #[error("HKDF Unsupported mode in derive")]
    HkdfUnsupportedMode,

    /// EC Missing Curve Name
    #[error("EC Missing Curve Name")]
    EcMissingCurveName,

    /// EC Unsupported Curve type
    #[error("EC Unsupported Curve type")]
    EcUnsupportedCurve,

    /// Get Collateral Error
    #[error("Error in getting device collateral")]
    GetCollateralError,

    /// Could not set load privkey method
    #[error("Could not set engine load private key method")]
    EngineSetLoadPrivKeyError,

    /// Could not set load pubkey method
    #[error("Could not set engine load public key method")]
    EngineSetLoadPubKeyError,

    /// Invalid key name
    #[error("Invalid key name {0}")]
    InvalidKeyName(String),

    /// Invalid key availability
    #[error("Invalid key availability")]
    InvalidKeyAvailability,

    /// Version error
    #[error("Error getting version")]
    VersionError,
}

impl From<OpenSSLError> for i32 {
    fn from(value: OpenSSLError) -> Self {
        #[cfg(feature = "openssl_3")]
        if matches!(
            value,
            OpenSSLError::PKeyMethodRetrievalError | OpenSSLError::CipherMethodRetrievalError
        ) {
            return ERR_R_UNSUPPORTED as i32;
        }

        match value {
            OpenSSLError::OpenSSLError(code) => code,
            OpenSSLError::IncorrectParam(_, _, _) | OpenSSLError::IncorrectHsmParam(_) => {
                ERR_R_PASSED_INVALID_ARGUMENT as i32
            }
            OpenSSLError::NullParam(_) => ERR_R_PASSED_NULL_PARAMETER as i32,
            OpenSSLError::AllocationFailed => ERR_R_MALLOC_FAILURE as i32,
            OpenSSLError::KeyGenerationError
            | OpenSSLError::EncryptionFailed
            | OpenSSLError::DecryptionFailed
            | OpenSSLError::SignFailed
            | OpenSSLError::VerifyFailed
            | OpenSSLError::InvalidKeyUsage => ERR_R_OPERATION_FAIL as i32,
            _ => ERR_R_INTERNAL_ERROR as i32,
        }
    }
}

pub type OpenSSLResult<T> = Result<T, OpenSSLError>;

// We cannot set the integer representation as c_int, so we use i32.
#[repr(i32)]
pub enum OpenSSLErrorCode {
    NotSupported = -2,
    Error = -1,
    Fail = 0,
    Success = 1,
}

impl From<OpenSSLErrorCode> for c_int {
    fn from(code: OpenSSLErrorCode) -> c_int {
        code as i32 as c_int
    }
}

/// Convert an OpenSSLResult into an OpenSSL 1/0 success/fail result
pub fn convert_result_int<T>(result: OpenSSLResult<T>) -> c_int {
    match result {
        Ok(_) => OpenSSLErrorCode::Success.into(),
        Err(e) => {
            tracing::warn!("convert_result_int: {e}");
            OpenSSLErrorCode::Fail.into()
        }
    }
}

/// Catch an unwinding and abort
pub fn on_unwind_abort<F: FnOnce() -> R + UnwindSafe, R>(func: F) -> R {
    let ret = catch_unwind(func);
    match ret {
        Ok(v) => v,
        Err(_) => {
            // We only get here after a panic, not if the result of func was Ok or Err.
            // If we do panic, there's nothing more we can really do safely than abort.
            // A panic is supposed to do that anyway, so this is what is desired.
            abort();
        }
    }
}
