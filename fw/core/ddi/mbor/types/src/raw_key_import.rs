// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

/// DDI `RawKeyImport` request (test hook, op 2008).
///
/// Injects host-supplied *plaintext* key material into the partition
/// vault, bypassing the wrap / unwrap path — a validation-only hook used
/// to load Known-Answer-Test vectors.  Parity with the legacy firmware
/// restricts the accepted `key_kind` to ECDH shared secrets
/// (`Secret256/384/521`) and variable-length HMAC keys
/// (`VarHmac256/384/512`); every other kind is rejected by the handler.
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiRawKeyImportReq<'a> {
    /// Raw plaintext key material (≤ 3072 bytes).
    #[ddi(id = 1, max_len = 3072)]
    pub raw: &'a mut DmaBuf,
    /// On-wire key kind the raw bytes are imported as.
    #[ddi(id = 2)]
    pub key_kind: DdiKeyType,
    /// Optional host key tag (app-scoped keys only).
    #[ddi(id = 3)]
    pub key_tag: Option<u16>,
    /// Target key properties (usage / availability / label).
    #[ddi(id = 4)]
    pub key_properties: DdiTargetKeyProperties<'a>,
}

/// DDI `RawKeyImport` response.
///
/// Mirrors the key-creating handlers: returns the new vault `key_id` and
/// a fresh masked-key envelope the host may persist and later re-import.
/// `bulk_key_id` is reserved for AES bulk variants and is always `None`
/// here.
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiRawKeyImportResp<'a> {
    #[ddi(id = 1)]
    pub key_id: u16,
    #[ddi(id = 2)]
    pub bulk_key_id: Option<u16>,
    #[ddi(id = 3, max_len = 3072)]
    pub masked_key: &'a [u8],
}

ddi_op_req_resp!(DdiRawKeyImport, 'a);
