// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn helper_test_action_cmd(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    action: DdiTestAction,
    crash_info: Option<DdiTestActionCrashReqInfo>,
    neg_test_id: Option<u32>,
    pin_policy_config: Option<DdiTestActionPinPolicyConfig>,
    force_pka_instance: Option<u8>,
    neg_pct_skip_cnt: Option<u8>,
    ecc_error_info: Option<DdiTestActionEccErrorInfo>,
    tdisp_interrupt_type: Option<DdiTestActionInterruptSimulationType>,
) -> DdiResult<DdiTestActionCmdResp> {
    let req = DdiTestActionCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::TestAction,
            sess_id: Some(session_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiTestActionReq {
            action,
            crash_info,
            neg_test_id,
            pin_policy_config,
            force_pka_instance,
            neg_pct_skip_cnt,
            ecc_error_info,
            tdisp_interrupt_type,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
