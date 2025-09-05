// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to install clippy

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to install clippy
#[derive(Parser)]
#[clap(about = "Install clippy")]
pub struct InstallClippy {}

impl Xtask for InstallClippy {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running install clippy");

        let sh = Shell::new()?;
        let rust_toolchain = sh.var("RUST_TOOLCHAIN").ok();
        let mut rust_toolchain_arg = Vec::new();
        let rust_toolchain_val;
        if rust_toolchain.is_some() {
            rust_toolchain_arg.push("--toolchain");
            rust_toolchain_val = rust_toolchain.unwrap_or("".to_string());
            rust_toolchain_arg.push(&rust_toolchain_val);
        }

        cmd!(sh, "rustup component add {rust_toolchain_arg...} clippy")
            .quiet()
            .run()?;

        log::trace!("done install clippy");
        Ok(())
    }
}
