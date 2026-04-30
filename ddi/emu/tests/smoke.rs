// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Smoke tests for `azihsm_ddi_emu`.

use azihsm_ddi_emu::DdiEmu;
use azihsm_ddi_emu::EMU_DEVICE_PATH;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_types::DdiApiRev;
use azihsm_ddi_types::DdiDeviceKind;
use azihsm_ddi_types::DdiGetApiRevCmdReq;
use azihsm_ddi_types::DdiGetApiRevReq;
use azihsm_ddi_types::DdiOp;
use azihsm_ddi_types::DdiReqHdr;

#[test]
fn dev_info_list_returns_emu_device() {
    let ddi = DdiEmu::default();
    let devs = ddi.dev_info_list();
    assert_eq!(devs.len(), 1);
    assert_eq!(devs[0].path, EMU_DEVICE_PATH);
}

#[test]
fn open_unknown_path_fails() {
    let ddi = DdiEmu::default();
    let res = ddi.open_dev("/dev/nonexistent");
    assert!(res.is_err(), "opening unknown path must fail");
}

#[test]
fn get_api_rev_round_trips_through_emulator() {
    let ddi = DdiEmu::default();
    let mut dev = ddi.open_dev(EMU_DEVICE_PATH).expect("open emu device");
    dev.set_device_kind(DdiDeviceKind::Virtual);

    let req = DdiGetApiRevCmdReq {
        hdr: DdiReqHdr {
            rev: None,
            op: DdiOp::GetApiRev,
            sess_id: None,
        },
        data: DdiGetApiRevReq {},
        ext: None,
    };

    let mut cookie = None;
    let resp = dev
        .exec_op(&req, &mut cookie)
        .expect("GetApiRev should succeed against the emulator");

    assert_eq!(resp.hdr.op, DdiOp::GetApiRev);
    assert_eq!(
        resp.data.min,
        DdiApiRev { major: 1, minor: 0 },
        "firmware should report min api rev 1.0",
    );
    assert_eq!(
        resp.data.max,
        DdiApiRev { major: 1, minor: 0 },
        "firmware should report max api rev 1.0",
    );
}
