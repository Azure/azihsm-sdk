// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for Vault.

#[cfg(feature = "fuzzing")]
use arbitrary::Arbitrary;

#[cfg_attr(feature = "fuzzing", derive(Arbitrary))]
#[derive(Default, Clone, Debug)]
///
/// Input to AES GCM operations
pub struct SessionAesGcmRequest {
    /// key_id
    pub key_id: u32,

    /// initialization vector
    pub iv: [u8; 12usize],

    /// tag.
    /// No op for AES GCM encryption
    /// Required for AES GCM decryption
    pub tag: Option<[u8; 16usize]>,

    /// session id
    pub session_id: u16,

    /// short app id
    pub short_app_id: u8,

    /// aad
    /// Additional authenticated data
    /// optional for encryption and
    /// decryption
    pub aad: Option<Vec<u8>>,
}

#[derive(Default, Clone)]
/// SessionAesGcmResponse
/// Output structure on AES GCM operations
pub struct SessionAesGcmResponse {
    /// Tag
    /// *`tag Input on gcm encryption. Optional`
    ///     Returned on successful GCM encryption
    pub tag: Option<[u8; 16usize]>,

    /// total_size
    /// Indicates the total size of the encrypted
    /// buffer or decrypted buffer
    pub total_size: u32,

    /// IV returned from the device
    pub iv: Option<[u8; 12usize]>,

    /// FIPS approved indication
    pub fips_approved: bool,
}

#[cfg_attr(feature = "fuzzing", derive(Arbitrary))]
#[derive(Default, Clone, Debug)]
/// SessionAesXtsRequest
/// Aes XTS request structure
pub struct SessionAesXtsRequest {
    /// dataUnitLen
    pub data_unit_len: usize,

    /// keyid1
    pub key_id1: u32,

    /// keyid2
    pub key_id2: u32,

    /// tweak vector
    pub tweak: [u8; 16usize],

    /// session id
    pub session_id: u16,

    /// short app id
    pub short_app_id: u8,
}

#[derive(Default, Clone)]
///SessionAesXtsResponse
/// Output structure of GCM XTS operations
///
pub struct SessionAesXtsResponse {
    /// data
    /// *`total size of output buffer`
    pub total_size: u32,

    /// FIPS approved indication
    pub fips_approved: bool,
}
