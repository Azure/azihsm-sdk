// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run install symcrypt

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::Xtask;
use crate::XtaskCtx;

#[cfg(not(target_os = "windows"))]
const UBUNTU_VER_DEFAULT: &str = "22.04";

/// Xtask to run install symcrypt
#[derive(Parser)]
#[clap(about = "Install symcrypt")]
pub struct InstallSymcrypt {
    /// Override Ubuntu version to install symcrypt for
    #[clap(long)]
    pub ubuntu_version: Option<String>,
}

impl Xtask for InstallSymcrypt {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running install symcrypt");

        let sh = Shell::new()?;

        #[cfg(target_os = "windows")]
        cmd!(
            sh,
            "powershell -File ../.pipelines/scripts/install-symcrypt.ps1"
        )
        .quiet()
        .run()?;

        log::trace!("done install symcrypt");
        Ok(())
    }
}
