// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

#[instrument(skip(event))]
pub(crate) fn handle_ctrl_event(event: CtrlEvent) -> Result<(), u32> {
    let app = MGMT_APP.get();
    let pal = app.pal();
    match event {
        CtrlEvent::Enable { ctrl_id } => {
            tracing::info!("CtrlEvent::Enable({})", ctrl_id);
            pal.set_ctrl_enable(ctrl_id)
        }
        CtrlEvent::Disable { ctrl_id } => {
            tracing::info!("CtrlEvent::Disable({})", ctrl_id);
            pal.set_ctrl_disable(ctrl_id)
        }
    }
}
