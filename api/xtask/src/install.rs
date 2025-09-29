// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run install

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run install
#[derive(Parser)]
#[clap(about = "Run Install")]
pub struct Install {
    /// Name of crate to install
    #[clap(long)]
    pub crate_name: String,
}

impl Xtask for Install {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running install");

        let sh = Shell::new()?;
        let rust_toolchain = sh.var("RUST_TOOLCHAIN").map(|s| format!("+{s}")).ok();

        // convert xtask parameters into cargo command arguments
        let crate_name = self.crate_name.as_str();

        cmd!(
            sh,
            "cargo {rust_toolchain...} install {crate_name} --locked"
        )
        .quiet()
        .run()?;

        log::trace!("done install");
        Ok(())
    }
}
