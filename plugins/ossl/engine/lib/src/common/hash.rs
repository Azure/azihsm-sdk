// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_uint;

use mcr_api_resilient::DigestKind;
use openssl_rust::safeapi::error::OpenSSLError;
use openssl_rust::safeapi::error::OpenSSLResult;
use openssl_rust::NID_sha1 as NID_SHA1;
use openssl_rust::NID_sha256 as NID_SHA256;
use openssl_rust::NID_sha384 as NID_SHA384;
use openssl_rust::NID_sha512 as NID_SHA512;

/// Get the hash type for sign/verify from NID
pub(crate) fn azihsm_hash_type(nid: c_uint) -> OpenSSLResult<Option<DigestKind>> {
    match nid {
        0 => Ok(None),
        NID_SHA1 => Ok(Some(DigestKind::Sha1)),
        NID_SHA256 => Ok(Some(DigestKind::Sha256)),
        NID_SHA384 => Ok(Some(DigestKind::Sha384)),
        NID_SHA512 => Ok(Some(DigestKind::Sha512)),
        _ => Err(OpenSSLError::HashNotSupported),
    }
}

/// Get the NID from the hash type
pub(crate) fn openssl_hash_nid(digest_kind: Option<DigestKind>) -> c_uint {
    match digest_kind {
        None => 0,
        Some(DigestKind::Sha1) => NID_SHA1,
        Some(DigestKind::Sha256) => NID_SHA256,
        Some(DigestKind::Sha384) => NID_SHA384,
        Some(DigestKind::Sha512) => NID_SHA512,
    }
}
