// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn helper_get_perf_log_chunk(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    chunk_id: u16,
) -> Result<DdiGetPerfLogChunkCmdResp, DdiError> {
    let req = DdiGetPerfLogChunkCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetPerfLogChunk,
            sess_id,
            rev,
        },
        data: DdiGetPerfLogChunkReq { chunk_id },
        ext: None,
    };

    let mut cookie = None;

    dev.exec_op(&req, &mut cookie)
}
