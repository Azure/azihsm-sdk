// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI `TestAction` wire types (op 2004).
//!
//! `TestAction` multiplexes a family of validation / fault-injection
//! sub-actions selected by [`DdiTestAction`].  This refactor bring-up
//! stands up the **framework**: the request mirrors the mainline host wire
//! layout (`Martichoras/api/ddi/test_hooks/src/test_ops.rs`) up to the slot
//! this firmware actually consumes (`force_pka_instance`, id 5), so the host
//! ABI decodes correctly.  Only `ForcePkaInstance` is handled today; other
//! action variants and their request sub-structs are ported incrementally as
//! each action is brought up.
//!
//! ## Wire-layout invariant
//! The `#[ddi(map)]` derive requires **contiguous** field ids and decodes
//! optional fields by *peeking* the next on-wire id, decoding only on an exact
//! match.  Any on-wire entry left unconsumed is a hard `InvalidLen` error.
//! Therefore every id up to the highest one this firmware needs must exist as a
//! declared field — even the intermediate slots we don't yet interpret — with
//! the **same id and type shape the host sends**.

use azihsm_fw_ddi_mbor_derive::Ddi;
use open_enum::open_enum;

use crate::*;

/// TestAction selector.  Discriminants MUST match mainline `DdiTestAction`
/// (`serde/ddi/types/src/test_ops.rs`) for host ABI parity.  Only the variants
/// this firmware handles are declared; `#[open_enum]` tolerates the other
/// on-wire values, which the handler rejects with `UnsupportedCmd`.
#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiTestAction {
    /// Skip IO with a Level-1 abort trigger.
    Level1SkipIo = 1,
}

/// TestAction request.
///
/// Field ids mirror mainline `DdiTestActionReq` (`serde/ddi/types/src/test_ops.rs`)
/// so the host's request decodes byte-for-byte.  MBOR maps are *sparse* — only
/// `Some` fields are serialized — so an action that carries no parameter (like
/// `Level1SkipIo`) rides the wire as just `[id 1 -> action]`.  This bring-up
/// therefore declares only `action`; parameterized actions add their fields as
/// contiguous id slots (matching the host's ids/types) as they are ported.
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionReq {
    /// Selected test action.
    #[ddi(id = 1)]
    pub action: DdiTestAction,
}

/// TestAction response.  `result` is an optional reusable 4-byte out param used
/// by certain actions; `None` for parameterless actions like `Level1SkipIo`.
/// Host id 1.
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionResp {
    #[ddi(id = 1)]
    pub result: Option<u32>,
}

ddi_op_req_resp!(DdiTestAction);

#[cfg(test)]
#[allow(clippy::unwrap_used, unsafe_code)]
mod tests {
    extern crate std;

    use azihsm_fw_ddi_mbor::DmaBuf;
    use azihsm_fw_ddi_mbor::MborDecode;
    use azihsm_fw_ddi_mbor::MborDecoder;
    use azihsm_fw_ddi_mbor::MborEncode;
    use azihsm_fw_ddi_mbor::MborEncoder;

    use super::*;

    /// Brand a plain test buffer as `&mut DmaBuf` so it can drive a decoder.
    fn dma(buf: &mut [u8]) -> &mut DmaBuf {
        // SAFETY: No real DMA hardware is involved in tests; the buffer is
        // only read/written by the codec, never submitted to a DMA engine.
        unsafe { DmaBuf::from_raw_mut(buf) }
    }

    /// A `Level1SkipIo` request carries only `action` on the wire
    /// (`[id 1 -> 1]`) and must round-trip through the exact host-encode ->
    /// firmware-decode path the dispatch handler runs.
    #[test]
    fn level1_skip_io_round_trips() {
        let req = DdiTestActionReq {
            action: DdiTestAction::Level1SkipIo,
        };
        let mut buf = [0u8; 32];
        let n = {
            let mut enc = MborEncoder::new(&mut buf);
            req.mbor_encode(&mut enc).unwrap();
            enc.position()
        };
        let mut dec = MborDecoder::new(dma(&mut buf[..n]));
        let got = DdiTestActionReq::mbor_decode(&mut dec).unwrap();
        assert_eq!(got.action, DdiTestAction::Level1SkipIo);
    }

    /// The response type round-trips its optional `result` out-param.
    #[test]
    fn resp_round_trips() {
        let mut buf = [0u8; 32];
        let resp = DdiTestActionResp { result: Some(0) };
        let n = {
            let mut enc = MborEncoder::new(&mut buf);
            resp.mbor_encode(&mut enc).unwrap();
            enc.position()
        };
        let mut dec = MborDecoder::new(dma(&mut buf[..n]));
        let got = DdiTestActionResp::mbor_decode(&mut dec).unwrap();
        assert_eq!(got.result, Some(0));
    }
}
