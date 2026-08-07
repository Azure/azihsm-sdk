// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

/// DDI `GetPrivKey` request (test hook, op 2005).
///
/// Reads back the raw plaintext material of a previously created or
/// imported key so a host Known-Answer-Test can confirm it landed
/// correctly.  Validation-only hook (`fips_validation_hooks`) — the
/// normal DDI surface never exposes private / secret key bytes.
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetPrivKeyReq {
    /// Vault key id to read back.
    #[ddi(id = 1)]
    pub key_id: u16,
}

/// DDI `GetPrivKey` response.
///
/// Returns the key's on-wire kind and its raw plaintext bytes.  The
/// `key_data` capacity (2564 bytes) is sized for the largest exportable
/// kind (an RSA-CRT private key); HMAC / secret keys occupy far less.
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetPrivKeyResp<'a> {
    /// On-wire kind of the returned key.
    #[ddi(id = 1)]
    pub key_kind: DdiKeyType,
    /// Raw plaintext key material.
    #[ddi(id = 2, max_len = 2564)]
    pub key_data: &'a [u8],
}

ddi_op_req_resp!(DdiGetPrivKey, resp 'a);
