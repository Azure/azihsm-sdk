// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI `AttestKey` command handler.
//!
//! Within an open session, produce a tagged COSE_Sign1 key-attestation
//! report over a vault key identified by `key_id`, and return it. The
//! report is signed **ES384 by the partition-identity (PID) key** — the
//! same signer the firmware uses for the other key-attestation reports.
//!
//! ECC-private and RSA-private keys embed their public component in the
//! report as an RFC 9052 COSE_Key. Every other kind (symmetric / bulk /
//! HMAC / secret, or any key with no public component) is still
//! attestable, but carries an **empty** COSE_Key (`public_key_size == 0`)
//! — matching the reference firmware and simulator.
//!
//! Deriving the ECC / RSA public component uses the PAL's
//! `ecc_priv_pub_key` / `rsa_priv_pub_key`. These are implemented on the
//! std PAL (and exercised by the emu tests); on the Uno PAL they are still
//! stubs pending PKA bring-up, so ECC / RSA attestation returns
//! `UnsupportedCmd` on Uno hardware until those methods land. Symmetric
//! attestation (empty COSE_Key) needs no public-key derivation and works
//! on any PAL.
//!
//! The command **persists nothing** — it reads the attested key, derives
//! its public component, and returns a signed report. No RSA verification
//! is performed anywhere: the report signature is always ES384 over the
//! PID key regardless of the attested key type.
//!
//! ## Endianness
//!
//! The attested key's public coordinates / modulus are baked into the
//! opaque signed `report` byte array, which the MBOR wire layer does not
//! convert. The PAL emits public keys in wire-LE, so this handler reverses
//! each component to **big-endian** before building the COSE_Key (RFC 9052
//! uses big-endian). Typed MBOR fields would instead rely on the wire
//! layer's `pre_encode`/`post_decode`; the report is the exception because
//! it is a signed opaque blob.

use azihsm_fw_core_crypto_key_report::key_report;
use azihsm_fw_core_crypto_key_report::AttestedPubKey;
use azihsm_fw_core_crypto_key_report::KeyFlags;
use azihsm_fw_core_crypto_key_report::KeyReportParams;
use azihsm_fw_core_crypto_key_report::APP_UUID_LEN;
use azihsm_fw_ddi_mbor_types::attest_key::DdiAttestKeyReq;
use azihsm_fw_ddi_mbor_types::attest_key::DdiAttestKeyResp;

use super::*;

/// Translate the attested key's vault attributes into report [`KeyFlags`].
fn key_flags_from_attrs(attrs: HsmVaultKeyAttrs) -> KeyFlags {
    KeyFlags::new()
        .with_is_imported(!attrs.local())
        .with_is_session_key(attrs.session())
        .with_is_generated(attrs.local())
        .with_can_encrypt(attrs.encrypt())
        .with_can_decrypt(attrs.decrypt())
        .with_can_sign(attrs.sign())
        .with_can_verify(attrs.verify())
        .with_can_wrap(attrs.wrap())
        .with_can_unwrap(attrs.unwrap())
        .with_can_derive(attrs.derive())
}

/// Reverse-copy `src` into `dst[..src.len()]` (wire-LE → big-endian).
fn reverse_copy(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter().rev()) {
        *d = *s;
    }
}

/// Handle `DdiAttestKeyCmd`.
pub(crate) async fn attest_key<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiAttestKeyReq = decoder.decode_data()?;
    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    let key_id = HsmKeyId::from(body.key_id);

    // Attested key metadata → report flags.
    let kind = pal.vault_key_kind(io, key_id)?;
    let attrs = pal.vault_key_attrs(io, key_id)?;
    let flags: u32 = key_flags_from_attrs(attrs).into();

    // `report_data` borrows directly from the decoded request buffer — no
    // copy; `key_report` validates its exact `REPORT_DATA_LEN` length.
    //
    // `app_uuid` / `vm_launch_id` are IO-lifetime allocations: they feed
    // both `key_report` passes, so they must live outside any scoped
    // allocator whose bump-mark reset could overlap the response buffer.
    let app_uuid = pal.dma_alloc(io, APP_UUID_LEN)?;
    app_uuid.copy_from_slice(&crate::session::session_app_id(
        pal,
        io,
        HsmSessId::from(sess_id),
    )?);

    let vm_launch_id = crate::part_state::part_vm_launch_guid(pal, io)?;

    // Derive the attested key's public component in big-endian COSE form.
    // The private key material is fetched only in the ECC/RSA arms; the
    // symmetric path has no public component and never touches it.
    let key = if let Ok(curve) = super::from_pal::ecc_curve(kind) {
        let priv_key = pal.vault_key(io, key_id)?;
        let coord_raw = curve.priv_key_len();
        let coord_wire = curve.wire_coord_len();
        let wire_len = curve.wire_pub_key_len();
        let pub_le = pal.dma_alloc(io, wire_len)?;
        // The serialize pass must write the full wire key; a short write
        // would leave stale DMA bytes in the tail of `pub_le` that must not
        // be baked into the report — treat any mismatch as a PAL fault.
        if pal
            .ecc_priv_pub_key(io, priv_key, Some(&mut *pub_le))
            .await?
            != wire_len
        {
            return Err(HsmError::InternalError);
        }
        let x_be = pal.dma_alloc(io, coord_raw)?;
        let y_be = pal.dma_alloc(io, coord_raw)?;
        reverse_copy(x_be, &pub_le[..coord_raw]);
        reverse_copy(y_be, &pub_le[coord_wire..coord_wire + coord_raw]);
        AttestedPubKey::Ecc {
            curve,
            x: x_be,
            y: y_be,
        }
    } else if let Ok(rsa) = super::from_pal::rsa_key(kind) {
        let priv_key = pal.vault_key(io, key_id)?;
        let mod_len = rsa.modulus_len();
        // The PAL emits the RSA public key as wire-LE `n_le || e_le`, where
        // `e_le` is a fixed 4-byte little-endian exponent, so the wire is
        // exactly `mod_len + RSA_PUB_EXP_LEN`. Any other length means the
        // PAL and our modulus-kind mapping disagree — a PAL/internal fault,
        // not a caller error.
        const RSA_PUB_EXP_LEN: usize = 4;
        let wire = mod_len + RSA_PUB_EXP_LEN;
        if pal.rsa_priv_pub_key(io, priv_key, None)? != wire {
            return Err(HsmError::InternalError);
        }
        let pub_le = pal.dma_alloc(io, wire)?;
        // The serialize pass must write exactly the queried length; a
        // shorter write would leave stale bytes in the tail of `pub_le`.
        if pal.rsa_priv_pub_key(io, priv_key, Some(&mut *pub_le))? != wire {
            return Err(HsmError::InternalError);
        }
        let n_be = pal.dma_alloc(io, mod_len)?;
        let e_be = pal.dma_alloc(io, RSA_PUB_EXP_LEN)?;
        reverse_copy(n_be, &pub_le[..mod_len]);
        reverse_copy(e_be, &pub_le[mod_len..wire]);
        AttestedPubKey::Rsa { n: n_be, e: e_be }
    } else {
        // Any other kind (symmetric / bulk / HMAC / secret) is attestable
        // but has no public component: emit an empty COSE_Key, matching the
        // reference firmware. The report still binds the key's flags and
        // report_data under the PID signature.
        AttestedPubKey::Symmetric
    };

    // Sign the report with the partition-identity (PID) key.
    let pid_priv = pal.vault_key(io, crate::part_state::part_id_key_id(pal, io)?)?;

    let params = KeyReportParams {
        key,
        flags,
        app_uuid,
        report_data: body.report_data,
        vm_launch_id,
        // MBOR AttestKey emits v1 reports (no policy hash).
        policy_hash: None,
    };

    // Two-pass build: query the exact report size, reserve the response
    // frame, then build the report straight into the reserved slot
    // (zero-copy — no intermediate buffer).
    let report_len = pal
        .alloc_scoped_async(io, async |a| {
            key_report(pal, io, a, &params, pid_priv, None).await
        })
        .await?;
    if report_len > DdiAttestKeyResp::MAX_REPORT_SIZE {
        return Err(HsmError::InternalError);
    }

    // Reserve the response (header + byte-array framing) sized to the
    // report.
    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder = super::encode_resp_hdr(
            &super::success_hdr_sess(hdr, DdiOp::AttestKey, sess_id),
            buf,
        )?;
        let layout = DdiAttestKeyResp::reserve(&mut encoder, report_len)?;
        Ok((encoder.position(), layout))
    })?;
    let frame = DdiAttestKeyResp::from_layout(resp, &layout);

    // Build the report directly into the reserved `report` slot.
    let written = pal
        .alloc_scoped_async(io, async |a| {
            key_report(pal, io, a, &params, pid_priv, Some(&mut *frame.report)).await
        })
        .await?;
    // The slot was reserved for exactly `report_len`; refuse to return a
    // short write — stale DMA bytes would otherwise leak to the host.
    if written != report_len {
        return Err(HsmError::InternalError);
    }
    Ok(resp)
}
