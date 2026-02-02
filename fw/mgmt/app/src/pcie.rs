// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

#[instrument(skip(event))]
pub(crate) fn handle_pcie_event(event: PcieEvent) -> Result<(), u32> {
    let app = MGMT_APP.get();
    match event {
        PcieEvent::PerstUp => {
            tracing::info!("PCIe PERST up event");
            app.pal().perst_up_done()
        }
        PcieEvent::PerstDown => {
            tracing::info!("PCIe PERST down event");
            app.pal().perst_down_done()
        }
        PcieEvent::FuncReset => {
            tracing::info!("PCIe FLR event");
            app.pal().flr_done()
        }
        PcieEvent::VirtFuncReset { ctrl_id } => {
            tracing::info!("PCIe VFLR({}) event", ctrl_id);
            app.pal().vflr_done(ctrl_id)
        }
    }
}
