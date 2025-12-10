// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub enum DdiTestActionContext {
    None,
    CrashInfo(DdiTestActionCrashReqInfo),
    NegTestId(u32),
    PinPolicyConfig(Option<DdiTestActionPinPolicyConfig>),
    ForcePkaInstance(u8),
    NegPctSkipCnt(u8),
    EccErrorInfo(DdiTestActionEccErrorInfo),
    TdispInterruptType(DdiTestActionInterruptSimulationType),
    UpdatedSvn(u64),
}

pub fn helper_test_action_cmd(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    action: DdiTestAction,
    context: DdiTestActionContext,
) -> DdiResult<DdiTestActionCmdResp> {
    let data = match context {
        DdiTestActionContext::CrashInfo(info) => DdiTestActionReq {
            action,
            crash_info: Some(info),
            neg_test_id: None,
            pin_policy_config: None,
            force_pka_instance: None,
            neg_pct_skip_cnt: None,
            ecc_error_info: None,
            tdisp_interrupt_type: None,
            updated_svn: None,
        },
        DdiTestActionContext::NegTestId(id) => DdiTestActionReq {
            action,
            crash_info: None,
            neg_test_id: Some(id),
            pin_policy_config: None,
            force_pka_instance: None,
            neg_pct_skip_cnt: None,
            ecc_error_info: None,
            tdisp_interrupt_type: None,
            updated_svn: None,
        },
        DdiTestActionContext::PinPolicyConfig(config) => DdiTestActionReq {
            action,
            crash_info: None,
            neg_test_id: None,
            pin_policy_config: config,
            force_pka_instance: None,
            neg_pct_skip_cnt: None,
            ecc_error_info: None,
            tdisp_interrupt_type: None,
            updated_svn: None,
        },
        DdiTestActionContext::ForcePkaInstance(instance) => DdiTestActionReq {
            action,
            crash_info: None,
            neg_test_id: None,
            pin_policy_config: None,
            force_pka_instance: Some(instance),
            neg_pct_skip_cnt: None,
            ecc_error_info: None,
            tdisp_interrupt_type: None,
            updated_svn: None,
        },
        DdiTestActionContext::NegPctSkipCnt(cnt) => DdiTestActionReq {
            action,
            crash_info: None,
            neg_test_id: None,
            pin_policy_config: None,
            force_pka_instance: None,
            neg_pct_skip_cnt: Some(cnt),
            ecc_error_info: None,
            tdisp_interrupt_type: None,
            updated_svn: None,
        },
        DdiTestActionContext::EccErrorInfo(info) => DdiTestActionReq {
            action,
            crash_info: None,
            neg_test_id: None,
            pin_policy_config: None,
            force_pka_instance: None,
            neg_pct_skip_cnt: None,
            ecc_error_info: Some(info),
            tdisp_interrupt_type: None,
            updated_svn: None,
        },
        DdiTestActionContext::TdispInterruptType(interrupt_type) => DdiTestActionReq {
            action,
            crash_info: None,
            neg_test_id: None,
            pin_policy_config: None,
            force_pka_instance: None,
            neg_pct_skip_cnt: None,
            ecc_error_info: None,
            tdisp_interrupt_type: Some(interrupt_type),
            updated_svn: None,
        },
        DdiTestActionContext::UpdatedSvn(svn) => DdiTestActionReq {
            action,
            crash_info: None,
            neg_test_id: None,
            pin_policy_config: None,
            force_pka_instance: None,
            neg_pct_skip_cnt: None,
            ecc_error_info: None,
            tdisp_interrupt_type: None,
            updated_svn: Some(svn),
        },
        DdiTestActionContext::None => DdiTestActionReq {
            action,
            crash_info: None,
            neg_test_id: None,
            pin_policy_config: None,
            force_pka_instance: None,
            neg_pct_skip_cnt: None,
            ecc_error_info: None,
            tdisp_interrupt_type: None,
            updated_svn: None,
        },
    };

    let req = DdiTestActionCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::TestAction,
            sess_id: Some(session_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data,
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
