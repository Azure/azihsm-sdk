// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI `GetPrivKey` command handler (validation hook, op 2005).
//!
//! Within an open session, read back the raw plaintext material of a
//! previously created / imported key and return it alongside the key's
//! on-wire kind.  This lets a host Known-Answer-Test confirm imported
//! key vectors landed correctly; the normal DDI surface never exposes
//! private / secret key bytes.
//!
//! No `partition_lock` is needed: the handler only performs read-only
//! vault lookups (`vault_key_kind` / `vault_key`).

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

use super::DDI_OP_GET_PRIV_KEY;
use super::FipsReqHdr;
use super::encode_resp;
use super::success_hdr_sess;
use crate::pal::UnoHsmPal;

/// DDI `GetPrivKey` request body.
#[derive(Debug, Ddi)]
#[ddi(map)]
struct DdiGetPrivKeyReq {
    /// Vault key id to read back.
    #[ddi(id = 1)]
    key_id: u16,
}

/// DDI `GetPrivKey` response body.
///
/// Returns the key's on-wire kind ([`DdiKeyType`]) and its raw
/// plaintext bytes.  The `key_data` capacity (3072 bytes) matches
/// the repo-wide key-material bound; the largest exportable kind is an
/// RSA-CRT private key, and HMAC / secret keys occupy far less.
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
/// The envelope map and header have already been consumed by the
/// caller; `decoder` is positioned at the request's data section.
pub(super) fn get_priv_key<'p>(
    pal: &'p UnoHsmPal,
    io: &impl HsmIo,
    decoder: &mut MborDecoder<'_>,
    hdr: &FipsReqHdr,
    req_len: usize,
) -> HsmResult<&'p DmaBuf> {
    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;

    let key = u8::mbor_decode(decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    if key != 1 {
        return Err(HsmError::DdiDecodeFailed);
    }
    let body = DdiGetPrivKeyReq::mbor_decode(decoder).map_err(|_| HsmError::DdiDecodeFailed)?;

    // Reject trailing bytes, matching the "fully consumed" rule the core
    // applies to every command it handles itself.
    if decoder.position() != req_len {
        return Err(HsmError::DdiDecodeFailed);
    }

    let key_id = HsmKeyId::from(body.key_id);

    // Resolve the stored kind and map it back to its on-wire type, then
    // borrow the committed plaintext (exact key length, no padding).
    let vault_kind = pal.vault_key_kind(io, key_id)?;
    let key_kind = vault_kind_ddi(vault_kind)?;
    let plaintext = pal.vault_key(io, key_id)?;

    let resp = pal.dma_alloc_var(io, |buf| {
        encode_resp(
            &success_hdr_sess(hdr, DDI_OP_GET_PRIV_KEY, sess_id),
            &DdiGetPrivKeyResp {
                key_kind,
                key_data: plaintext,
            },
            buf,
        )
    })?;

    Ok(resp)
}

/// Map a stored vault key kind back to its on-wire [`DdiKeyType`] for
/// the validation read-back.  Kinds a read-back cannot produce
/// (public-only, unwrap-only, or otherwise non-exportable) return
/// [`HsmError::InvalidKeyType`].
///
/// # Why this duplicates `core`'s `from_pal::vault_kind_ddi`
///
/// The core keeps the authoritative vault-kind → `DdiKeyType` table in
/// its `from_pal` module, but this hook deliberately keeps its own copy
/// rather than calling it:
///
/// * **Layering makes it unreachable.** `from_pal` lives in the HSM
///   *core* crate, which sits *above* the `HsmPal` boundary; this
///   dispatch hook lives *below* it, inside the platform PAL.  Calling
///   core from here would be a PAL → core (upward) dependency and
///   invert the layering, so the table is unreachable by construction —
///   not merely by `pub(crate)` visibility.  The only crate both sides
///   could share is the `DdiKeyType` *types* crate, but a vault-kind
///   *conversion policy* belongs with the handlers, not in a pure
///   wire-types crate.
/// * **The duplication is coincidental, not essential.** Core's table
///   answers "what tag do I stamp into a *production* masked-key blob?";
///   this one answers "what kind do I label a *test-only* read-back
///   with?" (a field the host harness does not even inspect).  They are
///   free to diverge, so this stays a small, self-contained copy gated
///   behind `fips_validation_hooks` and never ships in production.
fn vault_kind_ddi(kind: HsmVaultKeyKind) -> HsmResult<DdiKeyType> {
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
        HsmVaultKeyKind::VarLenHmacSha256 => Ok(DdiKeyType::VarHmac256),
        HsmVaultKeyKind::VarLenHmacSha384 => Ok(DdiKeyType::VarHmac384),
        HsmVaultKeyKind::VarLenHmacSha512 => Ok(DdiKeyType::VarHmac512),
        _ => Err(HsmError::InvalidKeyType),
    }
}
