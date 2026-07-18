// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `UnwrapKey` command handler.
//!
//! Implements `CKM_RSA_AES_KEY_WRAP` for the TBOR transport: within an open
//! session, unwrap a host-supplied wrapped-key blob with the partition's
//! RSA-2048 unwrapping key and return the recovered key as a **masked**
//! blob under the requested scope's masking key — the TBOR analogue of
//! MBOR `RsaUnwrap`, but re-masking the recovered key instead of vaulting
//! it.
//!
//! The unwrap + key-classification mechanics live in the protocol-neutral
//! [`azihsm_fw_hsm_key_unwrap`] / [`azihsm_fw_hsm_key_decode`] crates
//! (shared with MBOR `RsaUnwrap`).  This handler owns the TBOR concerns:
//! resolve the internal unwrapping key, decode the recovered material, mask
//! it under the scope, and — for the RSA / ECC classes — return the
//! re-derived wire public key.  Available to both Crypto-Officer and
//! Crypto-User sessions.

use azihsm_fw_core_crypto_key_masking::aead::mask;
use azihsm_fw_core_crypto_key_masking::aead::masked_blob_len;
use azihsm_fw_core_crypto_key_masking::aead::AeadAlg;
use azihsm_fw_core_crypto_key_masking::aead::MaskParams;
use azihsm_fw_ddi_tbor_types::HashAlgo;
use azihsm_fw_ddi_tbor_types::KeyClass;
use azihsm_fw_ddi_tbor_types::TborUnwrapKeyReq;
use azihsm_fw_ddi_tbor_types::TborUnwrapKeyResp;
use azihsm_fw_ddi_tbor_types::UNWRAP_MASKED_KEY_MAX_LEN;
use azihsm_fw_ddi_tbor_types::UNWRAP_PUB_KEY_MAX_LEN;
use azihsm_fw_hsm_key_decode::decode;
use azihsm_fw_hsm_key_decode::KeyClass as DecodeKeyClass;
use azihsm_fw_hsm_key_unwrap::unwrap_key;
use azihsm_fw_hsm_key_unwrap::UnwrapParams;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKeyScope;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::resolve_masking_key;
use super::validate_active_session;
use crate::part_state;

/// Envelope key-label recorded in the masked blob's `MaskedKeyMetadata`.
const UNWRAP_KEY_LABEL: &[u8] = b"UnwrappedKey";

/// Map the wire OAEP [`HashAlgo`] onto the firmware hash algorithm.
fn oaep_hsm_hash(algo: HashAlgo) -> HsmResult<HsmHashAlgo> {
    match algo {
        HashAlgo::Sha256 => Ok(HsmHashAlgo::Sha256),
        HashAlgo::Sha384 => Ok(HsmHashAlgo::Sha384),
        HashAlgo::Sha512 => Ok(HsmHashAlgo::Sha512),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Map the wire [`KeyClass`] onto the decode crate's key class.
fn decode_class(class: KeyClass) -> HsmResult<DecodeKeyClass> {
    match class {
        KeyClass::Aes => Ok(DecodeKeyClass::Aes),
        KeyClass::Rsa => Ok(DecodeKeyClass::Rsa),
        KeyClass::RsaCrt => Ok(DecodeKeyClass::RsaCrt),
        KeyClass::Ecc => Ok(DecodeKeyClass::Ecc),
        KeyClass::Hmac => Ok(DecodeKeyClass::Hmac),
        _ => Err(HsmError::UnsupportedCmd),
    }
}

/// Standard usage attributes for an imported key of `class`, plus the
/// requested `scope`.  Imported keys are never `local`.
fn attrs_for_class(class: KeyClass, scope: HsmKeyScope) -> HsmVaultKeyAttrs {
    let base = HsmVaultKeyAttrs::new().with_scope(scope);
    match class {
        // Symmetric cipher key: encrypt / decrypt.
        KeyClass::Aes => base.with_encrypt(true).with_decrypt(true),
        // RSA private key: sign / decrypt.
        KeyClass::Rsa | KeyClass::RsaCrt => base.with_sign(true).with_decrypt(true),
        // ECC private key: sign / derive.
        KeyClass::Ecc => base.with_sign(true).with_derive(true),
        // HMAC key: sign / verify.
        KeyClass::Hmac => base.with_sign(true).with_verify(true),
        _ => base,
    }
}

/// Handle a TBOR `UnwrapKey` request.
///
/// No partition lock or undo log is required: the command reads no mutable
/// partition state and **persists nothing** — it unwraps the caller's key,
/// masks it, and returns the blob.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = TborUnwrapKeyReq::decode(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id()));
    let scope = HsmKeyScope(req.scope().0);
    validate_active_session(pal, io, sess_id)?;

    let oaep_hash = oaep_hsm_hash(req.oaep_hash())?;
    let class = req.key_class();
    let dclass = decode_class(class)?;
    let wrapped_blob = req.wrapped_blob();

    // Resolve the partition's RSA-2048 unwrapping key id; an absent id means
    // generation is still pending, surfaced so the host retries (call
    // `GetUnwrappingKey` first).
    let unwrap_key_id = match part_state::part_unwrapping_key_id(pal, io) {
        Ok(id) => id,
        Err(HsmError::PartPropNotFound) => return Err(HsmError::PendingKeyGeneration),
        Err(e) => return Err(e),
    };

    // Platform identity bound into the masked blob (anti-rollback on
    // re-import).
    let svn = part_state::part_mfgr_svn(pal);
    let owner = u16::try_from(part_state::part_owner_svn(pal)).map_err(|_| HsmError::InvalidArg)?;
    let attrs = attrs_for_class(class, scope);

    // IO-scoped outputs sized for the largest supported key; they survive
    // the unwrap/decode scratch scope.  `masked_key` is zeroed because
    // `mask` requires the written prefix to be zero on entry.
    let masked_key = pal.dma_alloc_zeroed(io, UNWRAP_MASKED_KEY_MAX_LEN)?;
    let pub_key = pal.dma_alloc(io, UNWRAP_PUB_KEY_MAX_LEN)?;

    // Unwrap, decode, and mask inside an allocation scope so the (multi-KB
    // for RSA) unwrap/decode scratch is freed before the response is built.
    let (kind, masked_len, pub_len) = pal
        .alloc_scoped_async(
            io,
            async |alloc| -> HsmResult<(HsmVaultKeyKind, usize, usize)> {
                // Unwrap the blob (OAEP-decrypt the KEK, AES-KWP-unwrap the
                // payload) → raw recovered material, then decode into vault form.
                let material = unwrap_key(
                    pal,
                    io,
                    UnwrapParams {
                        unwrap_key_id,
                        oaep_hash,
                        wrapped_blob,
                    },
                )
                .await?;
                let decoded = decode(pal, io, material, dclass).await?;
                let kind = decoded.kind;

                // Copy the re-derived public key (RSA / ECC) into the IO-scoped
                // response buffer; symmetric keys have none.
                let pub_len = match &decoded.pub_key {
                    Some(pk) => {
                        if pk.len() > UNWRAP_PUB_KEY_MAX_LEN {
                            return Err(HsmError::InternalError);
                        }
                        pub_key[..pk.len()].copy_from_slice(&pk[..]);
                        pk.len()
                    }
                    None => 0,
                };

                // Mask the recovered key under the scope's masking key into the
                // IO-scoped `masked_key` buffer.
                let masked_len = masked_blob_len(AeadAlg::AesGcm256, decoded.material.len());
                if masked_len > UNWRAP_MASKED_KEY_MAX_LEN {
                    return Err(HsmError::InternalError);
                }
                let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;
                let key_label = alloc.dma_alloc(UNWRAP_KEY_LABEL.len())?;
                key_label.copy_from_slice(UNWRAP_KEY_LABEL);
                let params = MaskParams {
                    key_kind: kind,
                    key_attrs: attrs,
                    svn,
                    owner_seed_id: owner,
                    key_label,
                };
                mask(
                    pal,
                    io,
                    alloc,
                    AeadAlg::AesGcm256,
                    masking_key,
                    &params,
                    decoded.material,
                    Some(masked_key),
                )
                .await?;

                Ok((kind, masked_len, pub_len))
            },
        )
        .await?;

    encode_response(
        pal,
        io,
        kind,
        &masked_key[..masked_len],
        &pub_key[..pub_len],
    )
}

/// Encode the `UnwrapKey` response around the recovered key.
fn encode_response<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    kind: HsmVaultKeyKind,
    masked_key: &[u8],
    pub_key: &[u8],
) -> HsmResult<&'p DmaBuf> {
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborUnwrapKeyResp::encode(buf, 0, false)?
            .key_kind(kind.0)?
            .masked_key(masked_key)?
            .pub_key(pub_key)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
