// Copyright (C) Microsoft Corporation. All rights reserved.
use mcr_api_resilient::HsmError;
use winapi::shared::winerror::*;
use windows::core::HRESULT;

struct HresultError(HsmError);

impl From<HresultError> for HRESULT {
    fn from(value: HresultError) -> HRESULT {
        match value.0 {
            HsmError::InvalidParameter => HRESULT(E_INVALIDARG),
            _ => HRESULT(E_FAIL),
        }
    }
}
