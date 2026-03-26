// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared helpers for building AES-XTS wrapped key-pair blobs in tests.

use azihsm_api::*;

/// On-wire header for the AES-XTS key-pair blob:
/// `magic(u64 LE) || version(u16 LE) || key1_len(u16 LE) || key2_len(u16 LE) || reserved(u16 LE)`.
fn build_xts_wrapped_blob_header(key1_len: u16, key2_len: u16) -> [u8; 16] {
    // Keep tests agnostic to the internal Rust header struct.
    const WRAP_BLOB_MAGIC: u64 = 0x5354_584D_5348_5A41;
    const WRAP_BLOB_VERSION: u16 = 1;

    let mut hdr = [0u8; 16];
    hdr[0..8].copy_from_slice(&WRAP_BLOB_MAGIC.to_le_bytes());
    hdr[8..10].copy_from_slice(&WRAP_BLOB_VERSION.to_le_bytes());
    hdr[10..12].copy_from_slice(&key1_len.to_le_bytes());
    hdr[12..14].copy_from_slice(&key2_len.to_le_bytes());
    // reserved already zero
    hdr
}

/// Build a wrapped AES-XTS key-pair blob from two plaintext AES-256 halves.
pub(crate) fn build_xts_wrapped_blob(
    wrapping_pub_key: &HsmRsaPublicKey,
    hash: HsmHashAlgo,
    key1_plain: &[u8],
    key2_plain: &[u8],
) -> Vec<u8> {
    let mut wrap_algo_1 = HsmRsaAesWrapAlgo::new(hash, key1_plain.len());
    let key1_wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo_1, wrapping_pub_key, key1_plain)
        .expect("Failed to wrap XTS key1");

    let mut wrap_algo_2 = HsmRsaAesWrapAlgo::new(hash, key2_plain.len());
    let key2_wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo_2, wrapping_pub_key, key2_plain)
        .expect("Failed to wrap XTS key2");

    let key1_len = u16::try_from(key1_wrapped.len()).unwrap();
    let key2_len = u16::try_from(key2_wrapped.len()).unwrap();
    let header = build_xts_wrapped_blob_header(key1_len, key2_len);

    let mut blob = Vec::with_capacity(header.len() + key1_wrapped.len() + key2_wrapped.len());
    blob.extend_from_slice(&header);
    blob.extend_from_slice(&key1_wrapped);
    blob.extend_from_slice(&key2_wrapped);
    blob
}
