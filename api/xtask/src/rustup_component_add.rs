// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to add component via rustup

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to add component via rustup
#[derive(Parser)]
#[clap(about = "Adds component via rustup")]
pub struct RustupComponentAdd {
    /// Component to add
    #[clap(long)]
    pub component: String,

    /// Override toolchain to use for formatting
    #[clap(long)]
    pub toolchain: Option<String>,
}

impl Xtask for RustupComponentAdd {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running rustup component add");

        let sh = Shell::new()?;
        let rust_toolchain = self.toolchain.or_else(|| sh.var("RUST_TOOLCHAIN").ok());
        let mut rust_toolchain_arg = Vec::new();
        let rust_toolchain_val;
        if rust_toolchain.is_some() {
            rust_toolchain_arg.push("--toolchain");
            rust_toolchain_val = rust_toolchain.unwrap_or("".to_string());
            rust_toolchain_arg.push(&rust_toolchain_val);
        }
        let component_val = self.component;

        cmd!(
            sh,
            "rustup component add {rust_toolchain_arg...} {component_val}"
        )
        .quiet()
        .run()?;

        log::trace!("done rustup component add");
        Ok(())
    }
}
