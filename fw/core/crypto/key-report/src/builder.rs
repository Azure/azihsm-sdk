// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Runtime builder for ECC-P384 key-attestation reports.
//!
//! Mirrors the surface shape of [`hpke::ops::seal`]: async,
//! `pal + io + alloc` plumbing, query/copy on `Option<&mut [u8]>`.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmCrypto;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use bitfield_struct::bitfield;

use crate::template;

// ─── Public constants ───────────────────────────────────────────────────────

/// P-384 coordinate length (X or Y, big-endian raw).
pub const PUBLIC_KEY_COORD_LEN: usize = 48;

/// App UUID byte length (RFC 4122 binary form).
pub const APP_UUID_LEN: usize = 16;

/// Report-data field byte length.
pub const REPORT_DATA_LEN: usize = 128;

/// VM launch ID byte length.
pub const VM_LAUNCH_ID_LEN: usize = 16;

/// P-384 attestation private key length in bytes (raw scalar, LE wire format).
pub const PRIV_KEY_LEN: usize = 48;

/// ECDSA-P384 raw signature length (`r || s`).
pub const SIGNATURE_LEN: usize = 96;

/// Maximum bytes the payload can occupy (flags worst-case = 5 B).
pub const PAYLOAD_MAX_LEN: usize = template::HEAD_LEN + 5 + template::TAIL_LEN;

/// Maximum bytes the COSE Sig_structure can occupy.
pub const SIG_STRUCT_MAX_LEN: usize = SIG_STRUCT_FIXED_LEN + PAYLOAD_MAX_LEN;

/// Maximum bytes the final tagged COSE_Sign1 envelope can occupy.
pub const COSE_SIGN1_MAX_LEN: usize = COSE_SIGN1_FIXED_LEN + PAYLOAD_MAX_LEN;

// ─── COSE constants (RFC 9052 §4.4 + §4.2) ─────────────────────────────────

/// CBOR-encoded protected header `{ 1: -35, 3: "application/cbor" }`
/// wrapped in a 22-byte bstr.  ES384 = -35.
pub(crate) const PROTECTED_HEADER: [u8; 22] = [
    0xa2, 0x01, 0x38, 0x22, 0x03, 0x70, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x2f, 0x63, 0x62, 0x6f, 0x72,
];

/// COSE `Sig_structure` fixed bytes that precede the payload bstr.
///
/// Layout:
/// * `0x84`        array(4)
/// * `0x6A`        tstr(10) "Signature1"
/// * 10 ASCII bytes
/// * `0x56`        bstr(22) (protected_header)
/// * 22 bytes      `PROTECTED_HEADER`
/// * `0x40`        bstr(0)  (external_aad)
/// * `0x59 hi lo`  bstr(>=256) header for the payload
///
/// The 3-byte payload length header is filled in at runtime.
pub(crate) const SIG_STRUCT_FIXED_LEN: usize = 1 + 1 + 10 + 1 + 22 + 1 + 3;

/// COSE_Sign1 tagged envelope fixed bytes that precede the payload bstr.
///
/// Layout:
/// * `0xD2`        tag 18 (COSE_Sign1)
/// * `0x84`        array(4)
/// * `0x56`        bstr(22) (protected_header)
/// * 22 bytes      `PROTECTED_HEADER`
/// * `0xA0`        map(0) (unprotected_header)
/// * `0x59 hi lo`  bstr(>=256) header for the payload
///
/// The 3-byte payload length header is filled in at runtime.  The
/// signature bstr header (`0x58 0x60`) and the 96 signature bytes
/// follow the payload — accounted for separately below.
pub(crate) const COSE_SIGN1_PRE_PAYLOAD_LEN: usize = 1 + 1 + 1 + 22 + 1 + 3;

/// Bytes that follow the payload in the COSE_Sign1 envelope: the
/// signature bstr header (`0x58 0x60`) plus the 96-byte signature.
pub(crate) const COSE_SIGN1_POST_PAYLOAD_LEN: usize = 2 + SIGNATURE_LEN;

/// Total fixed (non-payload) bytes in the COSE_Sign1 envelope.
pub(crate) const COSE_SIGN1_FIXED_LEN: usize =
    COSE_SIGN1_PRE_PAYLOAD_LEN + COSE_SIGN1_POST_PAYLOAD_LEN;

const SIG_STRUCTURE_CONTEXT: [u8; 10] =
    [0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31];

// ─── KeyFlags bitfield (wire layout matches mcr-hsm and sim) ────────────────

/// Capability flags packed into the report's `flags: u32` field.
#[bitfield(u32)]
pub struct KeyFlags {
    pub is_imported: bool,
    pub is_session_key: bool,
    pub is_generated: bool,
    pub can_encrypt: bool,
    pub can_decrypt: bool,
    pub can_sign: bool,
    pub can_verify: bool,
    pub can_wrap: bool,
    pub can_unwrap: bool,
    pub can_derive: bool,
    #[bits(22)]
    _reserved: u32,
}

// ─── Inputs ─────────────────────────────────────────────────────────────────

/// Caller-supplied inputs for the attestation report payload.
///
/// Every byte slice is validated for exact length and rejected with
/// [`HsmError::InvalidArg`] on mismatch.
pub struct KeyReportParams<'a> {
    /// P-384 X coordinate of the attested public key, big-endian raw.
    /// Must be [`PUBLIC_KEY_COORD_LEN`] bytes.
    pub pk_x: &'a [u8],
    /// P-384 Y coordinate of the attested public key, big-endian raw.
    /// Must be [`PUBLIC_KEY_COORD_LEN`] bytes.
    pub pk_y: &'a [u8],
    /// Capability flags for the attested key.  Use
    /// `KeyFlags::new()…into()` to construct.
    pub flags: u32,
    /// Owning application UUID.  Must be [`APP_UUID_LEN`] bytes.
    pub app_uuid: &'a [u8],
    /// Caller-supplied report data.  Must be [`REPORT_DATA_LEN`] bytes.
    pub report_data: &'a [u8],
    /// VM launch ID.  Must be [`VM_LAUNCH_ID_LEN`] bytes.
    pub vm_launch_id: &'a [u8],
}

impl KeyReportParams<'_> {
    fn validate(&self) -> HsmResult<()> {
        if self.pk_x.len() != PUBLIC_KEY_COORD_LEN
            || self.pk_y.len() != PUBLIC_KEY_COORD_LEN
            || self.app_uuid.len() != APP_UUID_LEN
            || self.report_data.len() != REPORT_DATA_LEN
            || self.vm_launch_id.len() != VM_LAUNCH_ID_LEN
        {
            return Err(HsmError::InvalidArg);
        }
        Ok(())
    }
}

// ─── Single API ─────────────────────────────────────────────────────────────

/// Build a COSE_Sign1 ECC-P384 key-attestation report.
///
/// Mirrors [`azihsm_fw_core_crypto_hpke::ops::seal`] in shape:
///
/// * `pal`      — `HsmCrypto` (SHA-384 + ECDSA-P384) and `HsmAlloc`.
/// * `io`       — caller's IO scope.
/// * `alloc`    — scoped allocator for internal DMA scratch.
/// * `params`   — attested public key, flags, UUIDs, report data.
/// * `priv_key` — P-384 attestation private key (raw scalar, LE wire
///   format), exactly [`PRIV_KEY_LEN`] bytes, supplied as a [`DmaBuf`]
///   so it can be handed straight to
///   [`HsmEcc::ecc_sign`](azihsm_fw_hsm_pal_traits::HsmEcc::ecc_sign).
/// * `out`      — output buffer.  `None` runs in query mode and
///   returns the exact required size without touching the PAL.
///   `Some(buf)` writes the tagged COSE_Sign1 report into `buf[..size]`.
///
/// Output is byte-identical to mcr-hsm / `ddi/mbor/sim` for the same
/// inputs and the same signing key.
///
/// # Returns
///
/// * `Ok(size)` — bytes required (query) or bytes written (copy).
/// * `Err(HsmError::InvalidArg)` — any input slice has the wrong
///   length, or `buf.len() < size`.
/// * Other [`HsmError`] values propagated from the PAL.
pub async fn key_report<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    params: &KeyReportParams<'_>,
    priv_key: &DmaBuf,
    out: Option<&mut [u8]>,
) -> HsmResult<usize>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    params.validate()?;
    if priv_key.len() != PRIV_KEY_LEN {
        return Err(HsmError::InvalidArg);
    }

    let flags_width = canonical_u32_width(params.flags);
    let payload_len = template::HEAD_LEN + flags_width + template::TAIL_LEN;
    let total_len = COSE_SIGN1_FIXED_LEN + payload_len;

    let Some(out) = out else {
        return Ok(total_len);
    };
    if out.len() < total_len {
        return Err(HsmError::InvalidArg);
    }

    do_build(
        pal,
        io,
        alloc,
        params,
        priv_key,
        flags_width,
        payload_len,
        &mut out[..total_len],
    )
    .await?;
    Ok(total_len)
}

#[allow(clippy::too_many_arguments)]
async fn do_build<'a, P>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    params: &KeyReportParams<'_>,
    priv_key: &DmaBuf,
    flags_width: usize,
    payload_len: usize,
    out: &mut [u8],
) -> HsmResult<()>
where
    P: HsmCrypto + HsmAlloc + 'a,
{
    // 1. Build payload in DMA scratch.
    let payload_dma = alloc.dma_alloc(payload_len)?;
    write_payload(payload_dma, params, flags_width)?;

    // 2. Build Sig_structure in DMA scratch (constant prefix + payload).
    let sig_struct_len = SIG_STRUCT_FIXED_LEN + payload_len;
    let sig_struct_dma = alloc.dma_alloc(sig_struct_len)?;
    write_sig_struct(sig_struct_dma, payload_dma, payload_len)?;

    // 3. SHA-384 digest.
    let digest_dma = alloc.dma_alloc(48)?;
    pal.hash(
        io,
        azihsm_fw_hsm_pal_traits::HsmHashAlgo::Sha384,
        sig_struct_dma,
        digest_dma,
        false,
    )
    .await?;

    // 4. ECDSA-P384 sign — output is `r || s` in LE wire format.
    let sig_dma = alloc.dma_alloc(SIGNATURE_LEN)?;
    pal.ecc_sign(
        io,
        azihsm_fw_hsm_pal_traits::HsmEccCurve::P384,
        priv_key,
        digest_dma,
        sig_dma,
    )
    .await?;

    // 5. Compose the tagged COSE_Sign1 envelope into `out`.
    write_cose_sign1(out, payload_dma, payload_len, sig_dma)?;
    Ok(())
}

// ─── Payload encoder ────────────────────────────────────────────────────────

#[doc(hidden)]
pub fn write_payload(
    out: &mut [u8],
    params: &KeyReportParams<'_>,
    flags_width: usize,
) -> HsmResult<()> {
    let head = template::HEAD_LEN;
    let tail = template::TAIL_LEN;
    if out.len() != head + flags_width + tail {
        return Err(HsmError::InvalidArg);
    }

    // HEAD: copy template, then patch pk_x / pk_y holes.
    out[..head].copy_from_slice(&template::PAYLOAD_HEAD);
    out[template::PK_X_OFFSET..template::PK_X_OFFSET + PUBLIC_KEY_COORD_LEN]
        .copy_from_slice(params.pk_x);
    out[template::PK_Y_OFFSET..template::PK_Y_OFFSET + PUBLIC_KEY_COORD_LEN]
        .copy_from_slice(params.pk_y);

    // Canonical flags varint.
    write_canonical_u32(params.flags, &mut out[head..head + flags_width])?;

    // TAIL: copy template, then patch app_uuid / report_data / vm_launch_id.
    let tail_start = head + flags_width;
    out[tail_start..tail_start + tail].copy_from_slice(&template::PAYLOAD_TAIL);
    let app_uuid_off = tail_start + template::APP_UUID_OFFSET;
    out[app_uuid_off..app_uuid_off + APP_UUID_LEN].copy_from_slice(params.app_uuid);
    let report_data_off = tail_start + template::REPORT_DATA_OFFSET;
    out[report_data_off..report_data_off + REPORT_DATA_LEN].copy_from_slice(params.report_data);
    let vm_launch_id_off = tail_start + template::VM_LAUNCH_ID_OFFSET;
    out[vm_launch_id_off..vm_launch_id_off + VM_LAUNCH_ID_LEN].copy_from_slice(params.vm_launch_id);

    Ok(())
}

// ─── Sig_structure encoder ──────────────────────────────────────────────────

#[doc(hidden)]
pub fn write_sig_struct(out: &mut [u8], payload: &[u8], payload_len: usize) -> HsmResult<()> {
    if out.len() != SIG_STRUCT_FIXED_LEN + payload_len || payload.len() != payload_len {
        return Err(HsmError::InvalidArg);
    }
    out[0] = 0x84; // array(4)
    out[1] = 0x6a; // tstr(10)
    out[2..12].copy_from_slice(&SIG_STRUCTURE_CONTEXT);
    out[12] = 0x56; // bstr(22)
    out[13..35].copy_from_slice(&PROTECTED_HEADER);
    out[35] = 0x40; // bstr(0) external_aad
    out[36] = 0x59; // bstr(2-byte length)
    out[37] = ((payload_len >> 8) & 0xFF) as u8;
    out[38] = (payload_len & 0xFF) as u8;
    out[39..39 + payload_len].copy_from_slice(payload);
    Ok(())
}

// ─── COSE_Sign1 envelope encoder ────────────────────────────────────────────

#[doc(hidden)]
pub fn write_cose_sign1(
    out: &mut [u8],
    payload: &[u8],
    payload_len: usize,
    signature_le: &[u8],
) -> HsmResult<()> {
    if out.len() != COSE_SIGN1_FIXED_LEN + payload_len
        || payload.len() != payload_len
        || signature_le.len() != SIGNATURE_LEN
    {
        return Err(HsmError::InvalidArg);
    }
    out[0] = 0xD2; // tag 18 (COSE_Sign1)
    out[1] = 0x84; // array(4)
    out[2] = 0x56; // bstr(22) protected_header
    out[3..25].copy_from_slice(&PROTECTED_HEADER);
    out[25] = 0xA0; // map(0) unprotected_header
    out[26] = 0x59; // bstr(2-byte length) payload
    out[27] = ((payload_len >> 8) & 0xFF) as u8;
    out[28] = (payload_len & 0xFF) as u8;
    let payload_start = 29;
    out[payload_start..payload_start + payload_len].copy_from_slice(payload);

    let sig_header = payload_start + payload_len;
    out[sig_header] = 0x58; // bstr(1-byte length)
    out[sig_header + 1] = SIGNATURE_LEN as u8;
    // Signature: LE → BE for r and s independently.
    let sig_start = sig_header + 2;
    let half = SIGNATURE_LEN / 2;
    for i in 0..half {
        out[sig_start + i] = signature_le[half - 1 - i];
        out[sig_start + half + i] = signature_le[SIGNATURE_LEN - 1 - i];
    }
    Ok(())
}

// ─── Canonical u32 CBOR varint ──────────────────────────────────────────────

/// Returns the canonical CBOR byte length for an unsigned integer of
/// `value` magnitude under major type 0.
#[doc(hidden)]
pub fn canonical_u32_width(value: u32) -> usize {
    if value <= 23 {
        1
    } else if value <= 0xFF {
        2
    } else if value <= 0xFFFF {
        3
    } else {
        5
    }
}

/// Writes a canonical CBOR unsigned-integer encoding of `value` into
/// `out`.  `out.len()` must equal [`canonical_u32_width(value)`];
/// otherwise returns [`HsmError::InvalidArg`].
#[doc(hidden)]
pub fn write_canonical_u32(value: u32, out: &mut [u8]) -> HsmResult<()> {
    if out.len() != canonical_u32_width(value) {
        return Err(HsmError::InvalidArg);
    }
    if value <= 23 {
        out[0] = value as u8;
    } else if value <= 0xFF {
        out[0] = 0x18;
        out[1] = value as u8;
    } else if value <= 0xFFFF {
        out[0] = 0x19;
        out[1] = (value >> 8) as u8;
        out[2] = value as u8;
    } else {
        out[0] = 0x1A;
        out[1] = (value >> 24) as u8;
        out[2] = (value >> 16) as u8;
        out[3] = (value >> 8) as u8;
        out[4] = value as u8;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_widths() {
        assert_eq!(canonical_u32_width(0), 1);
        assert_eq!(canonical_u32_width(23), 1);
        assert_eq!(canonical_u32_width(24), 2);
        assert_eq!(canonical_u32_width(0xFF), 2);
        assert_eq!(canonical_u32_width(0x100), 3);
        assert_eq!(canonical_u32_width(0xFFFF), 3);
        assert_eq!(canonical_u32_width(0x1_0000), 5);
        assert_eq!(canonical_u32_width(u32::MAX), 5);
    }

    #[test]
    fn canonical_bytes() {
        let mut buf = [0u8; 5];
        write_canonical_u32(0, &mut buf[..1]).unwrap();
        assert_eq!(&buf[..1], &[0x00]);
        write_canonical_u32(24, &mut buf[..2]).unwrap();
        assert_eq!(&buf[..2], &[0x18, 0x18]);
        write_canonical_u32(0x1234, &mut buf[..3]).unwrap();
        assert_eq!(&buf[..3], &[0x19, 0x12, 0x34]);
        write_canonical_u32(0xDEAD_BEEF, &mut buf[..5]).unwrap();
        assert_eq!(&buf[..5], &[0x1A, 0xDE, 0xAD, 0xBE, 0xEF]);
    }
}
