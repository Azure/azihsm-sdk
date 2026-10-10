// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `TestAction` (`DdiOp` 2004) action router.
//!
//! The request data has the stable `{1: action, 2: payload}` shape.
//! This module decodes the action ID and routes the remaining data to the
//! action-specific module that owns its validation and behavior.
//! DDI MBOR uses canonical ascending field-ID order, matching the generated
//! `#[ddi(map)]` codecs, so field `1` precedes field `2`.

use azihsm_fw_ddi_mbor::MborDecode;
use azihsm_fw_ddi_mbor::MborDecoder;
use azihsm_fw_ddi_mbor::MborMap;
#[cfg(feature = "azihsm_test_hooks")]
use azihsm_fw_ddi_mbor_derive::Ddi;
use azihsm_fw_hsm_pal_traits::DmaBuf;
#[cfg(feature = "azihsm_test_hooks")]
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;

#[cfg(feature = "azihsm_test_hooks")]
use super::clear_user_credentials;
use super::common::ReqHdr;
#[cfg(feature = "azihsm_test_hooks")]
use super::common::encode_resp;
#[cfg(feature = "azihsm_test_hooks")]
use super::common::success_hdr;
#[cfg(feature = "fips_validation_hooks")]
use super::get_priv_key;
#[cfg(feature = "fips_validation_hooks")]
use super::raw_key_import;
#[cfg(feature = "azihsm_test_hooks")]
use super::trigger_crash;
use crate::pal::UnoHsmPal;

/// Maximum encoded size of one action-specific opaque payload.
///
/// This must match the host test-hooks `TEST_ACTION_PAYLOAD_MAX`.
pub(super) const TEST_ACTION_PAYLOAD_MAX: usize = 3584;

/// The response data shared by `TestAction` variants.
#[cfg(feature = "azihsm_test_hooks")]
#[derive(Debug, Ddi)]
#[ddi(map)]
struct DdiTestActionResp {
    /// Optional action-specific result.
    #[ddi(id = 1)]
    result: Option<u32>,
}

/// Test actions implemented by the Uno PAL.
///
/// Only actions with a compiled handler belong here. Unknown and
/// unimplemented action IDs remain indistinguishable and return
/// [`HsmError::UnsupportedCmd`].
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
enum SupportedTestAction {
    /// Inject a crash into the HSM/Admin/FP cores.
    #[cfg(feature = "azihsm_test_hooks")]
    TriggerCrash = 8,
    /// Clear the partition's stored user credential.
    #[cfg(feature = "azihsm_test_hooks")]
    ClearUserCredentials = 18,
    /// Read back private key material.
    #[cfg(feature = "fips_validation_hooks")]
    GetPrivKey = 25,
    /// Import raw key material.
    #[cfg(feature = "fips_validation_hooks")]
    RawKeyImport = 26,
}

/// Decoded action and field count from the outer TestAction request map.
#[derive(Debug, Copy, Clone)]
struct TestActionSelector {
    /// Action implemented by this firmware.
    action: SupportedTestAction,
    /// Number of fields in the outer TestAction request map.
    request_field_count: u8,
}

impl TryFrom<u32> for SupportedTestAction {
    type Error = HsmError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        #[cfg(feature = "azihsm_test_hooks")]
        if value == Self::TriggerCrash as u32 {
            return Ok(Self::TriggerCrash);
        }
        #[cfg(feature = "azihsm_test_hooks")]
        if value == Self::ClearUserCredentials as u32 {
            return Ok(Self::ClearUserCredentials);
        }
        #[cfg(feature = "fips_validation_hooks")]
        if value == Self::GetPrivKey as u32 {
            return Ok(Self::GetPrivKey);
        }
        #[cfg(feature = "fips_validation_hooks")]
        if value == Self::RawKeyImport as u32 {
            return Ok(Self::RawKeyImport);
        }
        Err(HsmError::UnsupportedCmd)
    }
}

/// Decode the action selector and route the action-specific request.
pub(super) async fn dispatch<'p>(
    pal: &'p UnoHsmPal,
    io: &impl HsmIo,
    hdr: &ReqHdr,
    decoder: &mut MborDecoder<'_>,
    request_len: usize,
) -> HsmResult<&'p DmaBuf> {
    let selector = decode_action_selector(decoder)?;

    match selector.action {
        #[cfg(feature = "azihsm_test_hooks")]
        SupportedTestAction::ClearUserCredentials => {
            clear_user_credentials::dispatch(
                pal,
                io,
                hdr,
                decoder,
                selector.request_field_count,
                request_len,
            )
            .await
        }
        #[cfg(feature = "azihsm_test_hooks")]
        SupportedTestAction::TriggerCrash => {
            trigger_crash::dispatch(pal, decoder, selector.request_field_count, request_len)
                .await
                .map(|never| match never {})
        }
        #[cfg(feature = "fips_validation_hooks")]
        SupportedTestAction::GetPrivKey => {
            let payload = decode_payload_bytes(decoder, selector.request_field_count, request_len)?;
            let payload_len = payload.len();
            let mut payload_decoder = MborDecoder::new(payload);
            get_priv_key::dispatch(pal, io, hdr, &mut payload_decoder, payload_len)
        }
        #[cfg(feature = "fips_validation_hooks")]
        SupportedTestAction::RawKeyImport => {
            let payload = decode_payload_bytes(decoder, selector.request_field_count, request_len)?;
            let payload_len = payload.len();
            let mut payload_decoder = MborDecoder::new(payload);
            raw_key_import::dispatch(pal, io, hdr, &mut payload_decoder, payload_len).await
        }
    }
}

fn decode_action_selector(decoder: &mut MborDecoder) -> HsmResult<TestActionSelector> {
    let request_map = MborMap::mbor_decode(decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    if request_map.0 != 2 {
        return Err(HsmError::DdiDecodeFailed);
    }

    let action_key = u8::mbor_decode(decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    if action_key != 1 {
        return Err(HsmError::DdiDecodeFailed);
    }
    let action = u32::mbor_decode(decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    let action = SupportedTestAction::try_from(action)?;

    Ok(TestActionSelector {
        action,
        request_field_count: request_map.0,
    })
}

/// Decode the opaque payload for a parameterized action.
///
/// Validates the shared outer `{1: action, 2: payload}` request shape,
/// enforces the payload bound, and requires complete consumption of both
/// the outer request and the nested MBOR payload.
#[cfg(feature = "azihsm_test_hooks")]
pub(super) fn decode_payload<'a, T>(
    decoder: &mut MborDecoder<'a>,
    request_field_count: u8,
    request_len: usize,
) -> HsmResult<T>
where
    T: MborDecode<'a>,
{
    let payload = decode_payload_bytes(decoder, request_field_count, request_len)?;

    let payload_len = payload.len();
    let mut payload_decoder = MborDecoder::new(payload);
    let request = T::mbor_decode(&mut payload_decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    if payload_decoder.position() != payload_len {
        return Err(HsmError::DdiDecodeFailed);
    }

    Ok(request)
}

/// Validate the request shape for a parameterless action.
///
/// Parameterless actions contain `{1: action, 2: bytes()}` and must carry an
/// empty payload with no trailing outer bytes.
#[cfg(feature = "azihsm_test_hooks")]
pub(super) fn expect_empty_payload(
    decoder: &mut MborDecoder<'_>,
    request_field_count: u8,
    request_len: usize,
) -> HsmResult<()> {
    let payload = decode_payload_bytes(decoder, request_field_count, request_len)?;
    if !payload.is_empty() {
        return Err(HsmError::DdiDecodeFailed);
    }

    Ok(())
}

fn decode_payload_bytes<'a>(
    decoder: &mut MborDecoder<'a>,
    request_field_count: u8,
    request_len: usize,
) -> HsmResult<&'a mut DmaBuf> {
    if request_field_count != 2 {
        return Err(HsmError::DdiDecodeFailed);
    }

    let payload_field_id = u8::mbor_decode(decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    if payload_field_id != 2 {
        return Err(HsmError::DdiDecodeFailed);
    }

    let (_pad, payload) = decoder
        .decode_byte_slice()
        .map_err(|_| HsmError::DdiDecodeFailed)?;
    if payload.len() > TEST_ACTION_PAYLOAD_MAX || decoder.position() != request_len {
        return Err(HsmError::DdiDecodeFailed);
    }

    Ok(payload)
}

/// Encode a successful action response with no action-specific result.
#[cfg(feature = "azihsm_test_hooks")]
pub(super) fn encode_success<'p>(
    pal: &'p UnoHsmPal,
    io: &impl HsmIo,
    hdr: &ReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let resp = pal.dma_alloc_var(io, |buf| {
        encode_resp(
            &success_hdr(hdr, hdr.sess_id),
            &DdiTestActionResp { result: None },
            buf,
        )
    })?;
    Ok(resp)
}
