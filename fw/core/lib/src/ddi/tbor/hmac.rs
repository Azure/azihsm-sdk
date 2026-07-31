// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `Hmac` command handler.
//!
//! Within an open session, compute an HMAC tag over a host-supplied
//! message using a caller-held **masked** HMAC key (the `masked_key`
//! returned by [`HmacGenerateKey`](super::hmac_generate_key) or imported
//! via unwrap).  The masked key's scope is read from its cleartext,
//! tag-bound metadata to select the masking key; the key is unmasked
//! on-device (verifying the AEAD tag), the MAC is computed, and the tag is
//! returned — nothing is persisted and the recovered key is wiped.
//!
//! The key must be an HMAC kind; its hash variant selects the MAC
//! algorithm and tag length (SHA-256 / 384 / 512 → 32 / 48 / 64 B).  A
//! non-HMAC key is rejected with `InvalidKeyType`; a key lacking the
//! `sign` (`C_Sign`) permission with `InvalidPermissions`.  Available to
//! both Crypto-Officer and Crypto-User sessions.

use azihsm_fw_core_crypto_key_masking::aead::peek_metadata;
use azihsm_fw_core_crypto_key_masking::aead::unmask;
use azihsm_fw_ddi_tbor_types::TborHmacReq;
use azihsm_fw_ddi_tbor_types::TborHmacResp;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_hsm_pal_traits::HsmSessId;

use super::resolve_masking_key;
use super::validate_active_session;

/// Handle a TBOR `Hmac` request.
///
/// No partition lock or undo log is required: the command reads no
/// mutable partition state and **persists nothing** — it unmasks the
/// caller's key **in place** in the request buffer, computes a tag, and
/// returns it.  There is no scratch copy of the masked blob or the
/// recovered key.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &mut DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    // `decode_mut` exposes `masked_key` as `&mut` (a slice of the request
    // buffer) so `unmask` can decrypt it in place, while `msg` is a
    // disjoint shared borrow.
    let req = TborHmacReq::decode_mut(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id));
    validate_active_session(pal, io, sess_id)?;

    // Peek the masked-key metadata (cleartext, tag-bound) to route to the
    // right masking key before unmasking.
    let scope = peek_metadata(req.masked_key)?.usage_flags().scope();
    let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;

    let masked_key = req.masked_key;
    let msg = req.msg;

    pal.alloc_scoped_async(io, async |alloc| -> HsmResult<&'p DmaBuf> {
        // Unmask the key in place and MAC into a scratch tag.  Capture the
        // result so the recovered key (now sitting in the request buffer)
        // can be wiped on EVERY path — success or failure — before
        // proceeding or propagating.  `view`'s borrow of `masked_key` ends
        // with the inner block, releasing it for the wipe.
        let mac_res = async {
            let view = unmask(pal, io, masking_key, masked_key).await?;
            // The kind must be an HMAC variant (selects the MAC algorithm
            // and tag length); a non-HMAC kind is rejected as
            // `InvalidKeyType`.
            let algo = crate::ddi::hmac_hash(view.key_kind)?;
            // Generating a MAC is a PKCS#11 `C_Sign` operation, so the key
            // must carry the `sign` permission.
            if !view.key_attrs.sign() {
                return Err(HsmError::InvalidPermissions);
            }
            // The recovered key (`view.target_key`, a `&DmaBuf` into the
            // request buffer) is used directly — no copy.
            let tag_len = algo.digest_len();
            let tag = alloc.dma_alloc(tag_len)?;
            pal.hmac_sign(io, algo, view.target_key, msg, tag).await?;
            Ok::<_, HsmError>((tag, tag_len))
        }
        .await;

        masked_key.zeroize();
        let (tag, tag_len) = mac_res?;
        encode_response(pal, io, &tag[..tag_len])
    })
    .await
}

/// Encode the `Hmac` response around the computed tag.
fn encode_response<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    tag: &[u8],
) -> HsmResult<&'p DmaBuf> {
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborHmacResp::encode(buf, 0, false)?.tag(tag)?.finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
