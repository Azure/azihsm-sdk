// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `GetApiRev` command.
//!
//! Both the request and response wire schemas live in
//! [`azihsm_fw_ddi_tbor_types::get_api_rev`] (shared with the firmware
//! handler in `fw/core/lib/src/ddi/tbor/get_api_rev.rs`). This module
//! adds the host-facing value types so [`exec_op_tbor`] returns owned
//! response values rather than borrowing `View<'a>` accessors over the
//! driver's IO scratch buffer.
//!
//! [`exec_op_tbor`]: ../../azihsm_ddi_interface/trait.DdiDev.html#method.exec_op_tbor

pub use azihsm_fw_ddi_tbor_types::TBOR_OP_GET_API_REV;

use crate::tbor;

/// Host-facing TBOR `GetApiRev` request. Carries no per-call data.
#[tbor]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborGetApiRevReq;

impl TborGetApiRevReq {
    /// Construct a `GetApiRev` request.
    #[inline]
    pub const fn new() -> Self {
        Self
    }
}

/// Host-facing TBOR `GetApiRev` response.
///
/// Reports the inclusive range of TBOR wire-protocol versions the
/// firmware understands.
#[tbor(response)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborGetApiRevResp {
    /// Lowest TBOR wire-protocol version the firmware speaks.
    pub min_protocol_version: u8,

    /// Highest TBOR wire-protocol version the firmware speaks.
    pub max_protocol_version: u8,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use azihsm_ddi_tbor_codec::PROTOCOL_VERSION;
    use azihsm_fw_ddi_tbor_types::TborGetApiRevReq as ReqSchema;
    use azihsm_fw_ddi_tbor_types::TborGetApiRevResp as RespSchema;

    use super::*;
    use crate::TborOpReq;
    use crate::TborResp;

    #[test]
    fn round_trip() {
        let mut req_buf = [0u8; 64];
        let req_bytes = TborGetApiRevReq::new()
            .encode_request(&mut req_buf)
            .expect("encode req");
        // 4-byte header + 1 TOC entry (4 bytes) = 8 bytes total.
        assert_eq!(req_bytes.len(), 8);
        assert_eq!(req_bytes[0], PROTOCOL_VERSION);
        assert_eq!(req_bytes[3], TBOR_OP_GET_API_REV);

        // Round-trip the request through the shared schema decoder.
        ReqSchema::decode(req_bytes).expect("schema decode");

        // Build a response via the shared schema encoder; decode through
        // the host wrapper.
        let mut resp_buf = [0u8; 64];
        let frame = RespSchema::encode(&mut resp_buf, 0, false)
            .unwrap()
            .min_protocol_version(1)
            .unwrap()
            .max_protocol_version(2)
            .unwrap()
            .finish();
        let decoded = TborGetApiRevResp::decode_response(frame.as_bytes()).expect("decode");
        assert_eq!(
            decoded,
            TborGetApiRevResp {
                min_protocol_version: 1,
                max_protocol_version: 2,
            }
        );
    }
}
