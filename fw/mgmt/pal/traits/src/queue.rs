// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

pub trait QueueMgr {
    fn create_sq(&self, sq_info: &SqInfo) -> MgmtPalResult<()>;

    fn delete_sq(&self, sq_id: u16) -> MgmtPalResult<()>;

    fn create_cq(&self, cq_info: &CqInfo) -> MgmtPalResult<()>;

    fn delete_cq(&self, cq_id: u16) -> MgmtPalResult<()>;
}
