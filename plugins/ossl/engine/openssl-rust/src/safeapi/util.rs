// Copyright (C) Microsoft Corporation. All rights reserved.
// Portions of this file derived from OpenSSL
// References: include/openssl/bn.h, include/openssl/evp.h

use std::ffi::c_int;
use std::ffi::c_uint;
use std::ptr::copy_nonoverlapping;
use std::slice;

use crate::BN_num_bits;
use crate::EVP_get_digestbyname;
use crate::OBJ_nid2sn;
use crate::BIGNUM;
use crate::EVP_MD;
use crate::OPENSSL_VER;

/// Convert a u8 pointer to a buffer, assuming the size is correct.
///
/// # Arguments
/// * `buf` - Pointer to buffer
/// * `buflen` - Size of the buffer
///
/// # Return
/// `Vec<u8>` Of the buffer
///
/// # Safety
/// * `buf` must point to valid memory, and `buflen` must be the correct size
pub unsafe fn u8_ptr_to_vec(buf: *const u8, buflen: usize) -> Vec<u8> {
    if buf.is_null() || buflen == 0 {
        return Vec::new();
    }

    // SAFETY: pointer must be allocated
    let s = slice::from_raw_parts(buf, buflen);
    s.to_vec()
}

/// Convert a slice to a u8 ptr, assuming the size is correct.
///
/// # Arguments
/// * `from` - Slice to convert from
/// * `to` - Pointer to buffer to write to
/// * `tolen` - Length of buffer pointed to by `to`
///
/// # Safety
/// * `to` must point to valid memory, and `tolen` must be the correct size
pub unsafe fn slice_to_u8_ptr(from: &[u8], to: *mut u8, tolen: usize) {
    if to.is_null() || tolen == 0 {
        return;
    }

    let tolen = tolen.min(from.len());

    // SAFETY: from is valid, to must be allocated
    unsafe {
        copy_nonoverlapping(from.as_ptr(), to, tolen);
    }
}

/// Get `EVP_MD` by NID
///
/// # Argument
/// * `nid` - NID of cipher
pub(crate) unsafe fn get_evp_md_by_nid(nid: c_uint) -> *const EVP_MD {
    // Taken from OpenSSL macro in evp.h
    unsafe { EVP_get_digestbyname(OBJ_nid2sn(nid as c_int)) }
}

/// Calculate size of bignum
///
/// # Arguments
/// * `num` - Pointer to bignum
///
/// # Safety
/// * `num` must point to a valid BIGNUM.
pub(crate) unsafe fn bn_num_bytes(num: *const BIGNUM) -> usize {
    if num.is_null() {
        return 0;
    }

    // Taken from OpenSSL macro in bn.h
    // SAFETY: num should be a valid BIGNUM
    let num_bits = unsafe { BN_num_bits(num) } as usize;
    num_bits.div_ceil(8)
}

/// Get OpenSSL major, minor, and patch versions
pub fn get_openssl_version() -> (c_uint, c_uint, c_uint) {
    (
        ((OPENSSL_VER >> 28) & 0x7f) as c_uint,
        ((OPENSSL_VER >> 20) & 0x7f) as c_uint,
        ((OPENSSL_VER >> 4) & 0x7f) as c_uint,
    )
}
