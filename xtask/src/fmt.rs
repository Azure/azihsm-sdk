// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run various repo-specific formatting checks

#[cfg(not(target_os = "windows"))]
use std::path::PathBuf;

use clap::Parser;
use xshell::cmd;

#[cfg(not(target_os = "windows"))]
use crate::clang_format::ClangFormat;
use crate::Xtask;
use crate::XtaskCtx;

/// Command for running clang-format (pinned to version 18 by default)
#[cfg(not(target_os = "windows"))]
const CLANG_FORMAT_CMD: &str = "clang-format-18";

/// Xtask to run various repo-specific formatting checks
#[derive(Parser)]
#[clap(about = "Run various formatting checks")]
pub struct Fmt {
    /// Attempt to fix any formatting issues
    #[clap(long)]
    pub fix: bool,

    /// Skip TOML formatting
    #[clap(long)]
    pub skip_taplo: bool,

    /// Skip C/C++ formatting
    #[clap(long)]
    pub skip_clang: bool,

    /// Override toolchain to use for formatting
    #[clap(long)]
    pub toolchain: Option<String>,
}

impl Xtask for Fmt {
    fn run(
        self,
        #[cfg(target_os = "windows")] _ctx: XtaskCtx,
        #[cfg(not(target_os = "windows"))] ctx: XtaskCtx,
    ) -> anyhow::Result<()> {
        log::trace!("running fmt");
        let sh = xshell::Shell::new()?;
        let rust_toolchain = self
            .toolchain
            .or_else(|| sh.var("RUST_TOOLCHAIN").ok())
            .map(|s| format!("+{s}"));

        // Check Fmt version
        let rust_toolchain_version = rust_toolchain.clone();
        cmd!(sh, "cargo {rust_toolchain_version...} fmt --version")
            .quiet()
            .run()?;

        // Check taplo-cli version
        if !self.skip_taplo {
            cmd!(sh, "taplo --version").quiet().run()?;
        }

        if let Some(toolchain) = rust_toolchain.as_ref() {
            log::trace!(
                "fmt toolchain override: fmt --toolchain={}",
                &toolchain[1..]
            );
        }

        let fmt_check = (!self.fix).then_some("--check");

        cmd!(sh, "cargo {rust_toolchain...} fmt -- {fmt_check...}")
            .quiet()
            .run()?;

        if !self.skip_taplo {
            log::trace!("running taplo fmt");
            cmd!(sh, "taplo fmt {fmt_check...}").quiet().run()?;
        }

        // Skip clang-format on Windows
        #[cfg(not(target_os = "windows"))]
        {
            if !self.skip_clang {
                log::trace!("running clang-format");
                // Check if clang-format is available
                if cmd!(sh, "{CLANG_FORMAT_CMD} --version")
                    .quiet()
                    .run()
                    .is_ok()
                {
                    let clang_format = ClangFormat {
                        clang_format_executable: CLANG_FORMAT_CMD.to_string(),
                        extensions: "c,h,C,H,cpp,hpp,cc,hh,c++,h++,cxx,hxx".to_string(),
                        recursive: true,
                        dry_run: false,
                        in_place: self.fix,
                        quiet: false,
                        color: "auto".to_string(),
                        exclude: vec![],
                        files: vec![
                            PathBuf::from(&ctx.root)
                                .join("napi")
                                .join("tests")
                                .join("cpp"),
                            #[cfg(target_os = "linux")]
                            PathBuf::from(&ctx.root)
                                .join("plugins")
                                .join("ossl_prov")
                                .join("src"),
                            #[cfg(target_os = "linux")]
                            PathBuf::from(&ctx.root)
                                .join("plugins")
                                .join("ossl_prov")
                                .join("inc"),
                        ],
                    };
                    clang_format.run(ctx)?;
                } else {
                    log::warn!("clang-format not found, skipping C/C++ formatting");
                }
            }
        }

        log::trace!("done fmt");
        Ok(())
    }
}
