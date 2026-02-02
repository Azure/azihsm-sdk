// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

#[instrument(skip(event))]
pub(crate) fn handle_ctrl_event(event: CtrlEvent) -> Result<(), u32> {
    let app = MGMT_APP.get();
    let pal = app.pal();
    match event {
        CtrlEvent::Enable { ctrl_id } => {
            tracing::info!("CtrlEvent::Enable({})", ctrl_id);
            let csts = pal.read_csts_reg(ctrl_id)?.with_rdy(true);
            pal.write_csts_reg(ctrl_id, csts)
        }
        CtrlEvent::Disable { ctrl_id } => {
            tracing::info!("CtrlEvent::Disable({})", ctrl_id);
            let csts = pal.read_csts_reg(ctrl_id)?.with_rdy(false);
            pal.write_csts_reg(ctrl_id, csts)
        }
    }
}
