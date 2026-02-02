// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub trait IoMgr {
    fn poll_sqe(&self) -> PalMgmtResult<u16>;

    fn send_cqe(&self, cq_id: u16, cqe_count: u16) -> PalMgmtResult<()>;
}
