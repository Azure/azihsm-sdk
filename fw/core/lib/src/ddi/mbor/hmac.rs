// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI Hmac command handler.
//!
//! Within an open session, compute an HMAC tag over a host-supplied
//! message using a vault-resident HMAC key (referenced by `key_id`)
//! and return the tag.
//!
//! The key must be an HMAC kind — either a fixed-length `_HmacSha*`
//! or a variable-length `VarLenHmacSha*` entry (the latter is what
//! HKDF / KBKDF derive in this firmware).  The key's hash variant
//! selects the MAC algorithm and tag length (SHA-256 / 384 / 512 →
//! 32 / 48 / 64 bytes).  A non-HMAC key is rejected with
//! `InvalidKeyType`; an unknown `key_id` with `KeyNotFound`.

use azihsm_fw_ddi_mbor_types::hmac::DdiHmacReq;
use azihsm_fw_ddi_mbor_types::hmac::DdiHmacResp;

use super::*;

/// Handle `DdiHmacCmd`.
///
/// No `partition_lock` is needed: this handler only reads vault state
/// (the HMAC key) and computes a tag — it performs no partition
/// mutation.
pub(crate) async fn hmac<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiHmacReq<'_> = decoder.decode_data()?;
    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    let key_id = HsmKeyId::from(body.key_id);

    // Resolve the key's hash variant — an unknown id surfaces as
    // `KeyNotFound`, a non-HMAC kind as `InvalidKeyType`.
    let algo = super::from_pal::hmac_hash(pal.vault_key_kind(io, key_id)?)?;
    let tag_len = algo.digest_len();

    // Generating a MAC is a PKCS#11 `C_Sign` operation, so the key
    // must carry `CKA_SIGN`.  An HMAC key derived for `derive`-only
    // use (a valid `for_var_hmac` outcome) is rejected here.
    if !pal.vault_key_attrs(io, key_id)?.sign() {
        return Err(HsmError::InvalidPermissions);
    }

    // Compute the tag into a DMA scratch slot, then encode it into the
    // response.  The key borrow is scoped so it is released before the
    // response allocation.
    let tag = pal.dma_alloc(io, tag_len)?;
    {
        let key = pal.vault_key(io, key_id)?;
        pal.hmac_sign(io, algo, key, body.msg, tag).await?;
    }

    let resp = pal.dma_alloc_var(io, |buf| {
        super::encode_resp(
            &super::success_hdr_sess(hdr, DdiOp::Hmac, sess_id),
            &DdiHmacResp {
                tag: &tag[..tag_len],
            },
            buf,
        )
    })?;
    Ok(resp)
}
