// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI `TestAction` command handler (op 2004).
//!
//! Multiplexes validation / fault-injection sub-actions selected by
//! [`DdiTestAction`].  This refactor bring-up wires a single placeholder
//! action, `Level1SkipIo`, to prove the dispatch → decode → encode path end
//! to end; every other action returns `UnsupportedCmd`.  New actions are
//! added as one `match` arm (plus a PAL hook if hardware access is needed) —
//! the dispatch/encode skeleton never changes.

use azihsm_fw_ddi_mbor_types::test_action::DdiTestAction;
use azihsm_fw_ddi_mbor_types::test_action::DdiTestActionReq;
use azihsm_fw_ddi_mbor_types::test_action::DdiTestActionResp;

use super::*;

/// Handle `DdiTestActionCmd`.
pub(crate) async fn test_action<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiTestActionReq = decoder.decode_data()?;

    // Optional 4-byte result some actions return; stays `None` unless an arm
    // sets it (the placeholder action does not — add `mut` when one does).
    let result: Option<u32> = None;

    match body.action {
        DdiTestAction::Level1SkipIo => {
            // Placeholder bring-up: the request is decoded and dispatched
            // here, but the Level-1 skip-IO backend is not yet wired.
            // Returning success lets the host confirm the TestAction hook is
            // reachable end to end.
            azihsm_fw_hsm_core_tracing::info!(
                "test_action",
                "Level1SkipIo (placeholder) dispatched"
            );
        }
        _ => return Err(HsmError::UnsupportedCmd),
    }

    let resp = pal.dma_alloc_var(io, |buf| {
        super::encode_resp(
            &super::success_hdr(hdr, DdiOp::TestAction),
            &DdiTestActionResp { result },
            buf,
        )
    })?;
    Ok(resp)
}
