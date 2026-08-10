// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `RsaModExp` command handler.
//!
//! Within an open session, perform the RSA private-key primitive
//! `x = y^d mod n` using a caller-held **masked** RSA private key
//! (imported via [`UnwrapKey`](super::unwrap_key) with the RSA / RSA-CRT
//! key class).  The key is unmasked **in place** in the request buffer (no
//! scratch copy), its modulus size / CRT form recovered from the blob's
//! key kind, and the result written straight into the reserved response
//! slot.  This is the raw modular exponentiation underlying RSA decrypt /
//! sign — the host applies and removes any padding.  This is the TBOR
//! analogue of MBOR `RsaModExp`, keyed by a masked blob instead of a vault
//! id.  There is no TBOR RSA key generation; RSA keys enter the device
//! only through `UnwrapKey`.
//!
//! Available to both Crypto-Officer and Crypto-User sessions.

use azihsm_fw_core_crypto_key_masking::aead::peek_metadata;
use azihsm_fw_core_crypto_key_masking::aead::unmask;
use azihsm_fw_ddi_tbor_types::RsaOp;
use azihsm_fw_ddi_tbor_types::TborRsaModExpReq;
use azihsm_fw_ddi_tbor_types::TborRsaModExpResp;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSessId;

use super::from_pal::rsa_key;
use super::resolve_masking_key;
use super::validate_active_session;

/// Handle a TBOR `RsaModExp` request.
///
/// No partition lock or undo log is required: the command reads no mutable
/// partition state and **persists nothing** — it unmasks the caller's key,
/// computes `y^d mod n`, and returns the result.  Takes `req_buf: &mut
/// DmaBuf` so the masked key can be unmasked in place (`decode_mut`).
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &mut DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = TborRsaModExpReq::decode_mut(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id));
    validate_active_session(pal, io, sess_id)?;

    // Map the wire op to the required usage attribute BEFORE unmasking,
    // rejecting an unknown `op_type` up front (so a garbage op does not
    // trigger an unmask).  The specific attribute is checked post-unmask.
    let require_sign = match RsaOp(req.op_type) {
        RsaOp::Sign => true,
        RsaOp::Decrypt => false,
        _ => return Err(HsmError::InvalidArg),
    };

    // The scope that masked this key is recorded (cleartext, tag-bound) in
    // the blob metadata; resolve its masking key before unmasking.  The
    // peek borrow is transient — it ends before the in-place unmask.
    let scope = peek_metadata(req.masked_key)?.usage_flags().scope();
    let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;

    // Unmask the private key in place, compute, and build the response
    // inside a block that yields a `Result`, so **every** post-unmask path
    // (success or error) falls through to the `masked_key` wipe below — the
    // recovered plaintext must never survive in the request buffer.
    let outcome: HsmResult<&'p DmaBuf> = async {
        let view = unmask(pal, io, masking_key, req.masked_key).await?;

        // Recover the modulus size / CRT form; a non-RSA-private blob is
        // rejected as `InvalidKeyType`.
        let key_size = rsa_key(view.key_kind)?;

        // The permitted operation depends on the key's usage attributes: a
        // decrypt primitive needs `decrypt`, a sign primitive needs `sign`.
        let permitted = if require_sign {
            view.key_attrs.sign()
        } else {
            view.key_attrs.decrypt()
        };
        if !permitted {
            return Err(HsmError::InvalidPermissions);
        }

        // The input integer `y` must be exactly the modulus length.
        let modulus_len = key_size.modulus_len();
        if req.y.len() != modulus_len {
            return Err(HsmError::InvalidArg);
        }

        // Reserve the modulus-sized `x` slot and have the PAL compute
        // `y^d mod n` straight into it — no scratch, no copy.
        let resp = pal.dma_alloc_var(io, |buf| {
            let frame = TborRsaModExpResp::encode(buf, 0, false)?
                .x_reserve(modulus_len)?
                .finish();
            Ok(frame.as_bytes().len())
        })?;
        {
            let out = TborRsaModExpResp::decode_mut(resp)?;
            pal.mod_exp_priv(io, key_size, view.target_key, req.y, out.x)
                .await?;
        }

        // Coerce the `&mut` response buffer to a shared `&DmaBuf` (preserving
        // the `'p` allocator lifetime) so the async block's output matches
        // the handler's `&'p DmaBuf` return.
        let resp: &'p DmaBuf = resp;
        Ok(resp)
    }
    .await;

    // Scrub the recovered plaintext key from the request buffer.
    req.masked_key.zeroize();
    outcome
}
