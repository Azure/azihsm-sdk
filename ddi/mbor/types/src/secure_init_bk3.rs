// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_ddi_mbor_derive::Ddi;

use crate::*;

/// DDI Encrypted BK3 payload (FIPS BK3 secure provisioning, Phase 4)
///
/// The 48-byte BK3 is encrypted with AES-CBC-256 under the transport key K2_aes
/// (derived from the Phase-3 shared secret S2). Two independent HMAC-SHA384 tags
/// are carried:
///   * `tag_transport` proves ciphertext/IV integrity in transit (key K2_hmac).
///   * `tag_pin` proves the caller knows the PIN set in Phase 2 (key K_pin,
///     derived from S2 and bound to the stored pin and id).
///
/// No id/pin are re-sent: the firmware uses the values stored during Phase 2.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, Clone, PartialEq, Eq)]
#[ddi(map)]
pub struct DdiEncryptedBk3 {
    /// Encrypted BK3 / ct_bk3 (48 bytes)
    #[ddi(id = 1)]
    pub encrypted_bk3: MborByteArray<48>,

    /// IV (iv2)
    #[ddi(id = 2)]
    pub iv: MborByteArray<16>,

    /// Nonce from device (nonce_2)
    #[ddi(id = 3)]
    pub nonce: [u8; 32],

    /// Transport integrity tag: HMAC-SHA384(K2_hmac, iv2 || ct_bk3 || nonce_2)
    #[ddi(id = 4)]
    pub tag_transport: [u8; 48],

    /// PIN authentication tag: HMAC-SHA384(K_pin, iv2 || ct_bk3 || nonce_2)
    #[ddi(id = 5)]
    pub tag_pin: [u8; 48],
}

/// DDI Secure Init BK3 Request Structure (FIPS BK3 secure provisioning, Phase 4)
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiSecureInitBk3Req {
    /// Encrypted BK3 payload
    #[ddi(id = 1)]
    pub encrypted_bk3: DdiEncryptedBk3,

    /// Host ephemeral Public Key (ECC 384)
    #[ddi(id = 2)]
    pub pub_key: DdiDerPublicKey,
}

/// DDI Secure Init BK3 Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiSecureInitBk3Resp {
    /// Output data (masked BK3)
    #[ddi(id = 1)]
    pub masked_bk3: MborByteArray<1024>,

    /// Launch ID for the partition
    #[ddi(id = 2)]
    pub vm_launch_guid: [u8; 16],
}

ddi_op_req_resp!(DdiSecureInitBk3);
