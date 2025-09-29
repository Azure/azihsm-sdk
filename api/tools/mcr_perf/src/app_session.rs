// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub(crate) fn helper_open_app_session(
    dev: &<DdiTest as Ddi>::Dev,
    app_id: [u8; 16],
    app_pin: [u8; 16],
    seed: [u8; 48],
) -> DdiResult<(u16, u8)> {
    loop {
        let (encrypted_credential, pub_key) =
            encrypt_userid_pin_for_open_session(dev, app_id, app_pin, seed);

        let req = DdiOpenSessionCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::OpenSession,
                sess_id: None,
                rev: Some(DdiApiRev { major: 1, minor: 0 }),
            },
            data: DdiOpenSessionReq {
                encrypted_credential,
                pub_key,
            },
            ext: None,
        };
        let mut cookie = None;
        let resp = dev.exec_op(&req, &mut cookie);

        if let Err(error) = resp.as_ref() {
            // Retry if the error is DdiStatus::NonceMismatch, fail otherwise.
            assert!(
                matches!(error, DdiError::DdiStatus(DdiStatus::NonceMismatch)),
                "Only NonceMismatch error is allowed but received different error: {:?}",
                error
            );
        } else {
            return resp.map(|resp| (resp.data.sess_id, resp.data.short_app_id));
        }
    }
}

pub(crate) fn helper_close_app_session(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
) -> DdiResult<()> {
    let req = DdiCloseSessionCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::CloseSession,
            sess_id: Some(app_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiCloseSessionReq {},
        ext: None,
    };

    let mut cookie = None;

    let resp = dev.exec_op(&req, &mut cookie);
    resp.map(|_| ())
}

pub(crate) fn helper_open_app_session_and_close(
    dev: &<DdiTest as Ddi>::Dev,
    app_id: [u8; 16],
    app_pin: [u8; 16],
    seed: [u8; 48],
) -> DdiResult<()> {
    let (app_sess_id, _) = helper_open_app_session(dev, app_id, app_pin, seed)?;
    helper_close_app_session(dev, app_sess_id)
}

#[allow(unused)]
pub(crate) fn helper_reset_function(
    dev: &<DdiTest as Ddi>::Dev,
    mngr_sess_id: u16,
) -> DdiResult<()> {
    let req = DdiResetFunctionCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::ResetFunction,
            sess_id: Some(mngr_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiResetFunctionReq {},
        ext: None,
    };

    let mut cookie = None;

    let resp = dev.exec_op(&req, &mut cookie);
    resp.map(|_| ())
}

pub(crate) fn helper_get_perf_log_chunk(
    dev: &<DdiTest as Ddi>::Dev,
    mngr_sess_id: u16,
    chunk_id: u16,
) -> DdiResult<Vec<u8>> {
    let req = DdiGetPerfLogChunkCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetPerfLogChunk,
            sess_id: Some(mngr_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetPerfLogChunkReq { chunk_id },
        ext: None,
    };

    let mut cookie = None;

    let resp = dev.exec_op(&req, &mut cookie);
    resp.map(|resp| resp.data.chunk[..resp.data.chunk_len as usize].to_vec())
}
