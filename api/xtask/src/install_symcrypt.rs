// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run install symcrypt

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run install symcrypt
#[derive(Parser)]
#[clap(about = "Install symcrypt")]
pub struct InstallSymcrypt {}

impl Xtask for InstallSymcrypt {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running install symcrypt");

        let sh = Shell::new()?;

        #[cfg(target_os = "windows")]
        cmd!(
            sh,
            "powershell -File ../.github/workflows/scripts/install-symcrypt.ps1"
        )
        .quiet()
        .run()?;
        #[cfg(not(target_os = "windows"))]
        cmd!(
            sh,
            "powershell -File ../.github/workflows/scripts/install-symcrypt.sh"
        )
        .quiet()
        .run()?;

        log::trace!("done install symcrypt");
        Ok(())
    }
}
