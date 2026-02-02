// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub trait QueueMgr {
    fn create_sq(&self, sq_info: &SqInfo) -> PalMgmtResult<()>;

    fn delete_sq(&self, sq_id: u16) -> PalMgmtResult<()>;

    fn create_cq(&self, cq_info: &CqInfo) -> PalMgmtResult<()>;

    fn delete_cq(&self, cq_id: u16) -> PalMgmtResult<()>;
}
