// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `TestAction::AesGcm` handler.
//!
//! Runs one AES-GCM operation through the PAL's [`HsmAes`] GCM methods on
//! a caller-supplied key, IV, AAD, and text, and returns the result. A host
//! known-answer test uses it to check the platform's AES-GCM, including a
//! partial last block, against published test vectors. The key comes from
//! the caller, so no device secret is involved.

use azihsm_fw_core_crypto_gcm_buf::format_gcm_buf;
use azihsm_fw_core_crypto_gcm_buf::gcm_buf_len;
use azihsm_fw_core_crypto_gcm_buf::padded_aad_len;
use azihsm_fw_ddi_mbor::MborDecoder;
use azihsm_fw_ddi_mbor_derive::Ddi;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAes;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;

use super::common::ReqHdr;
use super::common::encode_resp;
use super::common::success_hdr;
use super::test_action::decode_payload;
use crate::pal::UnoHsmPal;

/// AES-GCM IV length in bytes.
const IV_LEN: usize = 12;

/// AES-GCM tag length in bytes.
const TAG_LEN: usize = 16;

/// The PAL GCM method to run. Values match the host's `DdiAesGcmOp`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Op {
    /// [`HsmAes::gcm_encrypt`], separate source and destination buffers.
    Encrypt,
    /// [`HsmAes::gcm_encrypt_in_place`].
    EncryptInPlace,
    /// [`HsmAes::gcm_decrypt`], separate source and destination buffers.
    Decrypt,
    /// [`HsmAes::gcm_decrypt_in_place`].
    DecryptInPlace,
}

impl TryFrom<u32> for Op {
    type Error = HsmError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Encrypt),
            2 => Ok(Self::EncryptInPlace),
            3 => Ok(Self::Decrypt),
            4 => Ok(Self::DecryptInPlace),
            _ => Err(HsmError::InvalidArg),
        }
    }
}

/// DDI `AesGcm` request data.
#[derive(Debug, Ddi)]
#[ddi(map)]
struct DdiAesGcmReq<'a> {
    /// PAL GCM method to run (see [`Op`]).
    #[ddi(id = 1)]
    op: u32,
    /// AES key (16, 24, or 32 bytes).
    #[ddi(id = 2, max_len = 32)]
    key: &'a [u8],
    /// 12-byte IV.
    #[ddi(id = 3, max_len = 12)]
    iv: &'a [u8],
    /// Additional authenticated data.
    #[ddi(id = 4, max_len = 256)]
    aad: &'a [u8],
    /// Plaintext to encrypt, or ciphertext to decrypt.
    #[ddi(id = 5, max_len = 512)]
    text: &'a [u8],
    /// Tag to verify. Required to decrypt, and rejected for encrypt.
    #[ddi(id = 6, max_len = 16)]
    tag: Option<&'a [u8]>,
}

/// DDI `AesGcm` response data.
#[derive(Debug, Ddi)]
#[ddi(map)]
struct DdiAesGcmResp<'a> {
    /// Ciphertext from encrypt, or plaintext from decrypt.
    #[ddi(id = 1, max_len = 512)]
    text: &'a [u8],
    /// Tag from encrypt; absent for decrypt.
    #[ddi(id = 2, max_len = 16)]
    tag: Option<&'a [u8]>,
}

/// Validate and execute `TestAction::AesGcm`.
pub(super) async fn dispatch<'p>(
    pal: &'p UnoHsmPal,
    io: &impl HsmIo,
    hdr: &ReqHdr,
    decoder: &mut MborDecoder<'_>,
    request_field_count: u8,
    request_len: usize,
) -> HsmResult<&'p DmaBuf> {
    let request: DdiAesGcmReq<'_> = decode_payload(decoder, request_field_count, request_len)?;
    execute(pal, io, hdr, &request).await
}

async fn execute<'p>(
    pal: &'p UnoHsmPal,
    io: &impl HsmIo,
    hdr: &ReqHdr,
    request: &DdiAesGcmReq<'_>,
) -> HsmResult<&'p DmaBuf> {
    let op = Op::try_from(request.op)?;
    let decrypt = matches!(op, Op::Decrypt | Op::DecryptInPlace);
    if request.iv.len() != IV_LEN {
        return Err(HsmError::InvalidArg);
    }
    let expected_tag = match (decrypt, request.tag) {
        (true, Some(tag)) if tag.len() == TAG_LEN => Some(tag),
        (false, None) => None,
        _ => return Err(HsmError::InvalidArg),
    };

    let key = pal.dma_alloc(io, request.key.len())?;
    key.copy_from_slice(request.key);
    let iv = pal.dma_alloc(io, IV_LEN)?;
    iv.copy_from_slice(request.iv);
    let tag = pal.dma_alloc_zeroed(io, TAG_LEN)?;
    if let Some(expected_tag) = expected_tag {
        tag.copy_from_slice(expected_tag);
    }

    // Lay the input out as `[padded AAD | text]`, as the PAL GCM methods expect.
    let buf_len = gcm_buf_len(request.aad.len(), request.text.len());
    let src = pal.dma_alloc(io, buf_len)?;
    let aad_len = format_gcm_buf(request.aad, request.text, src);
    let text_start = padded_aad_len(aad_len);

    let out: &DmaBuf = match op {
        Op::Encrypt => {
            let dst = pal.dma_alloc(io, buf_len)?;
            pal.gcm_encrypt(io, key, iv, aad_len, src, dst, tag).await?;
            dst
        }
        Op::EncryptInPlace => {
            pal.gcm_encrypt_in_place(io, key, iv, aad_len, src, tag)
                .await?;
            src
        }
        Op::Decrypt => {
            let dst = pal.dma_alloc(io, buf_len)?;
            pal.gcm_decrypt(io, key, iv, aad_len, tag, src, dst).await?;
            dst
        }
        Op::DecryptInPlace => {
            pal.gcm_decrypt_in_place(io, key, iv, aad_len, tag, src)
                .await?;
            src
        }
    };
    let text: &[u8] = out.get(text_start..).ok_or(HsmError::InvalidArg)?;
    let tag_bytes: &[u8] = tag;
    let tag = if decrypt { None } else { Some(tag_bytes) };

    let resp = pal.dma_alloc_var(io, |buf| {
        encode_resp(
            &success_hdr(hdr, hdr.sess_id),
            &DdiAesGcmResp { text, tag },
            buf,
        )
    })?;
    Ok(resp)
}
