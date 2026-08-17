// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `AesEncryptDecrypt` command handler.
//!
//! Within an open session, AES-CBC encrypt or decrypt a host-supplied
//! message using a caller-held **masked** AES key (the `masked_key` from
//! [`AesGenerateKey`](super::aes_generate_key) or imported via
//! [`UnwrapKey`](super::unwrap_key)).  The masked key's scope is read from
//! its cleartext, tag-bound metadata to select the masking key; the key is
//! unmasked **in place** in the request buffer (verifying the AEAD tag),
//! the AES-CBC transform runs zero-copy — reading the request message and
//! writing the transformed message plus updated chaining IV straight into
//! the response buffer — and nothing is persisted; the recovered key is
//! wiped.  This is the TBOR analogue of MBOR `AesEncryptDecrypt`, keyed by
//! a masked blob rather than a vault `key_id`.
//!
//! The key must be a non-bulk AES kind (`InvalidKeyType` otherwise) and
//! must carry the permission matching the direction (`encrypt` for
//! `Encrypt`, `decrypt` for `Decrypt`; `InvalidPermissions` otherwise).
//! Available to both Crypto-Officer and Crypto-User sessions.

use azihsm_fw_core_crypto_key_masking::aead::peek_metadata;
use azihsm_fw_core_crypto_key_masking::aead::unmask;
use azihsm_fw_ddi_tbor_types::AesOp;
use azihsm_fw_ddi_tbor_types::TborAesEncryptDecryptReq;
use azihsm_fw_ddi_tbor_types::TborAesEncryptDecryptResp;
use azihsm_fw_ddi_tbor_types::AES_IV_LEN;
use azihsm_fw_ddi_tbor_types::AES_MSG_MAX_LEN;
use azihsm_fw_hsm_pal_traits::AesOp as PalAesOp;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKeyScope;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::resolve_masking_key;
use super::validate_active_session;

/// AES-CBC block size in bytes — also the required IV length.
const AES_BLOCK_LEN: usize = AES_IV_LEN;

/// Map the wire [`AesOp`] onto the PAL [`PalAesOp`].  An unrecognized
/// discriminant is rejected with [`HsmError::InvalidArg`].
fn pal_aes_op(op: AesOp) -> HsmResult<PalAesOp> {
    match op {
        AesOp::Encrypt => Ok(PalAesOp::Encrypt),
        AesOp::Decrypt => Ok(PalAesOp::Decrypt),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Require an unmasked key to be a non-bulk AES kind (128 / 192 / 256).
/// The XTS / GCM bulk kinds are not valid for the CBC transform.
fn assert_aes_kind(kind: HsmVaultKeyKind) -> HsmResult<()> {
    match kind {
        HsmVaultKeyKind::Aes128 | HsmVaultKeyKind::Aes192 | HsmVaultKeyKind::Aes256 => Ok(()),
        _ => Err(HsmError::InvalidKeyType),
    }
}

/// Unmask the AES key **in place** and run the CBC transform, reading
/// `input` and writing the ciphertext / chaining IV straight into the
/// response slots `out_msg` / `out_iv`.
///
/// `masked_key` is a `&mut` slice of the request buffer: `unmask` decrypts
/// it in place and the recovered `target_key` is used directly — no scratch
/// copy of the blob or the key.  `input` (request) and `out_msg` (response
/// slot) are distinct buffers, so the AES engine performs the read → write
/// with no intermediate copy.  The recovered key is wiped on every path.
#[allow(clippy::too_many_arguments)]
async fn transform<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    op: PalAesOp,
    scope: HsmKeyScope,
    sess_id: HsmSessId,
    masked_key: &mut DmaBuf,
    input: &DmaBuf,
    iv: &DmaBuf,
    out_msg: &mut DmaBuf,
    out_iv: &mut DmaBuf,
) -> HsmResult<()> {
    let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;

    // Unmask in place; validate the key is an AES key that permits the
    // requested direction; transform straight from the recovered key into
    // the response.  Capture the result so the recovered key (now in the
    // request buffer) is wiped on EVERY path — `view`'s borrow of
    // `masked_key` ends with the inner block, releasing it for the wipe.
    let crypt_res = async {
        let view = unmask(pal, io, masking_key, masked_key).await?;
        assert_aes_kind(view.key_kind)?;
        // Encrypt is a `C_Encrypt` op, Decrypt a `C_Decrypt` op; the key
        // must carry the matching permission.
        let permitted = match op {
            PalAesOp::Encrypt => view.key_attrs.encrypt(),
            PalAesOp::Decrypt => view.key_attrs.decrypt(),
        };
        if !permitted {
            return Err(HsmError::InvalidPermissions);
        }
        pal.aes_cbc_enc_dec(io, op, view.target_key, input, iv, out_msg, Some(out_iv))
            .await
    }
    .await;

    masked_key.zeroize();
    crypt_res
}

/// Handle a TBOR `AesEncryptDecrypt` request.
///
/// No partition lock or undo log is required: the command reads no mutable
/// partition state and **persists nothing** — it unmasks the caller's key
/// and transforms the message into the response buffer.
///
/// Fully zero-copy: `decode_mut` exposes the request `masked_key` as `&mut`
/// so `unmask` decrypts it in place (no blob / key scratch copy); the
/// response `msg` / `iv` slots are **reserved** and filled in place
/// (`decode_mut`) by the AES engine, which reads the request message and
/// writes the ciphertext / chaining IV straight into the response.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &mut DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    // `decode_mut` exposes `masked_key` as `&mut` (a slice of the request
    // buffer) so `unmask` can decrypt it in place; `msg` / `iv` are disjoint
    // shared borrows.
    let req = TborAesEncryptDecryptReq::decode_mut(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id));
    validate_active_session(pal, io, sess_id)?;

    let op = pal_aes_op(AesOp(req.op))?;

    // IV must be exactly one block; the message must be non-empty, a whole
    // number of blocks, and within the wire max (single source of truth:
    // `AES_MSG_MAX_LEN`).
    if req.iv.len() != AES_BLOCK_LEN {
        return Err(HsmError::InvalidArg);
    }
    if req.msg.is_empty()
        || !req.msg.len().is_multiple_of(AES_BLOCK_LEN)
        || req.msg.len() > AES_MSG_MAX_LEN
    {
        return Err(HsmError::InvalidArg);
    }
    let msg_len = req.msg.len();

    // Peek the masked-key metadata (cleartext, tag-bound) to route to the
    // right masking key before unmasking.
    let scope = peek_metadata(req.masked_key)?.usage_flags().scope();

    // Build the response with the `msg` / `iv` slots reserved (sized but
    // unwritten) — no data copy at encode time.
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborAesEncryptDecryptResp::encode(buf, 0, false)?
            .msg_reserve(msg_len)?
            .iv_reserve(AES_BLOCK_LEN)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;

    let masked_key = req.masked_key;
    let msg = req.msg;
    let iv = req.iv;

    // Fill the reserved slots in place: unmask the key in the request buffer
    // and have the AES engine write straight into the response.  The view is
    // scoped so its borrow of `resp` ends before `resp` is returned.
    {
        let out = TborAesEncryptDecryptResp::decode_mut(resp)?;
        transform(
            pal, io, op, scope, sess_id, masked_key, msg, iv, out.msg, out.iv,
        )
        .await?;
    }

    Ok(resp)
}
