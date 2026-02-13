// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

pub trait IoMgr {
    fn poll_sqe(&self) -> MgmtPalResult<u16>;

    fn send_cqe(&self, cq_id: u16, cqe_count: u16) -> MgmtPalResult<()>;
}
