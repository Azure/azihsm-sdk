// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI `GetPrivKey` command handler (validation hook, op 2005).
//!
//! Within an open session, read back the raw plaintext material of a
//! previously created or imported key and return it alongside the key's
//! on-wire kind. This lets a host Known-Answer-Test confirm imported
//! key vectors landed correctly; the normal DDI surface never exposes
//! private or secret key bytes.
//!
//! Session-scoped keys are readable only from the session that created
//! them: a key bound to another session is reported as
//! [`HsmError::KeyNotFound`], so a session cannot export another
//! session's material by guessing its ID.
//!
//! No `partition_lock` is needed: the handler only performs read-only
//! vault lookups.
//!
//! Two kinds of keys are deliberately not readable back: AES bulk
//! (fast-path) kinds, whose vault entry is a two-byte bulk-key reference
//! rather than raw AES material this PAL can recover, and device-internal
//! keys, which are device-owned and never leave the HSM. Both are refused
//! with [`HsmError::InvalidKeyType`].

use azihsm_fw_ddi_mbor::MborDecode;
use azihsm_fw_ddi_mbor::MborDecoder;
use azihsm_fw_ddi_mbor_derive::Ddi;
use azihsm_fw_ddi_mbor_types::DdiKeyType;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKeyId;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmVault;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::common::ReqHdr;
use super::common::encode_resp;
use super::common::success_hdr;
use crate::pal::UnoHsmPal;

/// DDI `GetPrivKey` request data.
#[derive(Debug, Ddi)]
#[ddi(map)]
struct DdiGetPrivKeyReq {
    /// Vault key ID to read back.
    #[ddi(id = 1)]
    key_id: u16,
}

/// DDI `GetPrivKey` response data.
///
/// Returns the key's on-wire kind ([`DdiKeyType`]) and its raw
/// plaintext bytes. The `key_data` capacity matches the repository-wide
/// key-material bound.
#[derive(Debug, Ddi)]
#[ddi(map)]
struct DdiGetPrivKeyResp<'a> {
    /// On-wire kind of the returned key.
    #[ddi(id = 1)]
    key_kind: DdiKeyType,
    /// Raw plaintext key material.
    #[ddi(id = 2, max_len = 3072)]
    key_data: &'a [u8],
}

/// Handle `DdiGetPrivKeyCmd`.
///
/// The envelope map, header, and data field ID have already been consumed
/// by the caller; `decoder` is positioned at the request data map.
pub(super) fn dispatch<'p>(
    pal: &'p UnoHsmPal,
    io: &impl HsmIo,
    hdr: &ReqHdr,
    decoder: &mut MborDecoder<'_>,
    request_len: usize,
) -> HsmResult<&'p DmaBuf> {
    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    let request = DdiGetPrivKeyReq::mbor_decode(decoder).map_err(|_| HsmError::DdiDecodeFailed)?;

    if decoder.position() != request_len {
        return Err(HsmError::DdiDecodeFailed);
    }

    let key_id = HsmKeyId::from(request.key_id);

    if pal
        .vault_key_session_binding(io, key_id)?
        .is_some_and(|bound| bound != sess_id)
    {
        return Err(HsmError::KeyNotFound);
    }

    let vault_kind = pal.vault_key_kind(io, key_id)?;

    if matches!(
        vault_kind,
        HsmVaultKeyKind::AesXtsBulk256
            | HsmVaultKeyKind::AesGcmBulk256
            | HsmVaultKeyKind::AesGcmBulk256Unapproved
    ) {
        return Err(HsmError::InvalidKeyType);
    }

    if pal.vault_key_attrs(io, key_id)?.internal() {
        return Err(HsmError::InvalidKeyType);
    }

    let key_kind = vault_kind_ddi(vault_kind)?;
    let plaintext = pal.vault_key(io, key_id)?;

    let resp = pal.dma_alloc_var(io, |buf| {
        encode_resp(
            &success_hdr(hdr, Some(sess_id)),
            &DdiGetPrivKeyResp {
                key_kind,
                key_data: plaintext,
            },
            buf,
        )
    })?;

    Ok(resp)
}

/// Map a stored vault key kind back to its on-wire [`DdiKeyType`].
///
/// This intentionally duplicates the HSM core's mapping because the
/// test hook lives below the PAL boundary and cannot depend upward on
/// the core. The mappings must remain aligned so key kinds round-trip
/// through import, read-back, masking, and re-import.
pub(super) fn vault_kind_ddi(kind: HsmVaultKeyKind) -> HsmResult<DdiKeyType> {
    match kind {
        HsmVaultKeyKind::Rsa2kPrivate => Ok(DdiKeyType::Rsa2kPrivate),
        HsmVaultKeyKind::Rsa3kPrivate => Ok(DdiKeyType::Rsa3kPrivate),
        HsmVaultKeyKind::Rsa4kPrivate => Ok(DdiKeyType::Rsa4kPrivate),
        HsmVaultKeyKind::Rsa2kPrivateCrt => Ok(DdiKeyType::Rsa2kPrivateCrt),
        HsmVaultKeyKind::Rsa3kPrivateCrt => Ok(DdiKeyType::Rsa3kPrivateCrt),
        HsmVaultKeyKind::Rsa4kPrivateCrt => Ok(DdiKeyType::Rsa4kPrivateCrt),
        HsmVaultKeyKind::Ecc256Private => Ok(DdiKeyType::Ecc256Private),
        HsmVaultKeyKind::Ecc384Private => Ok(DdiKeyType::Ecc384Private),
        HsmVaultKeyKind::Ecc521Private => Ok(DdiKeyType::Ecc521Private),
        HsmVaultKeyKind::Aes128 => Ok(DdiKeyType::Aes128),
        HsmVaultKeyKind::Aes192 => Ok(DdiKeyType::Aes192),
        HsmVaultKeyKind::Aes256 => Ok(DdiKeyType::Aes256),
        HsmVaultKeyKind::AesXtsBulk256 => Ok(DdiKeyType::AesXtsBulk256),
        HsmVaultKeyKind::AesGcmBulk256 => Ok(DdiKeyType::AesGcmBulk256),
        HsmVaultKeyKind::AesGcmBulk256Unapproved => Ok(DdiKeyType::AesGcmBulk256Unapproved),
        HsmVaultKeyKind::Secret256 => Ok(DdiKeyType::Secret256),
        HsmVaultKeyKind::Secret384 => Ok(DdiKeyType::Secret384),
        HsmVaultKeyKind::Secret521 => Ok(DdiKeyType::Secret521),
        HsmVaultKeyKind::_HmacSha256 => Ok(DdiKeyType::HmacSha256),
        HsmVaultKeyKind::_HmacSha384 => Ok(DdiKeyType::HmacSha384),
        HsmVaultKeyKind::_HmacSha512 => Ok(DdiKeyType::HmacSha512),
        HsmVaultKeyKind::VarLenHmacSha256 => Ok(DdiKeyType::VarHmac256),
        HsmVaultKeyKind::VarLenHmacSha384 => Ok(DdiKeyType::VarHmac384),
        HsmVaultKeyKind::VarLenHmacSha512 => Ok(DdiKeyType::VarHmac512),
        _ => Err(HsmError::InvalidKeyType),
    }
}
