// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Backend setup shared by every TBOR integration test.
//!
//! Both `emu` and `mock` advertise exactly one synthetic device; the
//! per-command tests just need a [`DdiDev`] handle to call
//! `exec_op_tbor`, so [`open_dev`] hides the boilerplate.

use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;

/// Open the first device advertised by the configured backend
/// (`emu` or `mock`). Panics if the backend lists no devices — which
/// would be a bug in the backend itself, not in the caller.
pub fn open_dev() -> <AzihsmDdi as Ddi>::Dev {
    let ddi = AzihsmDdi::default();
    let infos = ddi.dev_info_list();
    let info = infos.first().expect("backend should advertise a device");
    ddi.open_dev(&info.path).expect("open test backend device")
}
