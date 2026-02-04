// Copyright (C) Microsoft Corporation. All rights reserved.

use crate::nextest_history_cache::write_history::write_history;
use crate::Xtask;
use crate::XtaskCtx;

/// Run nextest report
#[derive(clap::Parser)]
pub struct NextestHistory {
    // Add command-line arguments here as needed
}

impl Xtask for NextestHistory {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running nextest-history");

        write_history()?;

        log::trace!("done nextest-history");
        Ok(())
    }
}
