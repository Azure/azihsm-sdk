// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to generate and verify the committed C header for the native API.
//!
//! The header produced by `cbindgen` from `azihsm_api_native` is checked into
//! the repository (at [`HEADER_PATH`]) so it can be reviewed and consumed
//! directly. This xtask regenerates it with the same pinned `cbindgen` and
//! `clang-format-18` used elsewhere, then either writes the committed copy
//! (`--fix`) or verifies the committed copy is up to date (default), failing
//! with a diff when it has drifted from the Rust FFI.
//! Generation and checking are skipped on Windows; Linux CI enforces freshness.

#[cfg(not(target_os = "windows"))]
use std::fs;
#[cfg(not(target_os = "windows"))]
use std::path::Path;

#[cfg(not(target_os = "windows"))]
use anyhow::bail;
#[cfg(not(target_os = "windows"))]
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
#[cfg(not(target_os = "windows"))]
use xshell::cmd;
#[cfg(not(target_os = "windows"))]
use xshell::Shell;

use crate::Xtask;
use crate::XtaskCtx;

/// The native crate that cbindgen parses.
#[cfg(not(target_os = "windows"))]
const CRATE_DIR: &str = "api/native";

/// The cbindgen configuration driving header generation.
#[cfg(not(target_os = "windows"))]
const CONFIG_PATH: &str = "api/native/cbindgen.toml";

/// The committed, reviewed header kept in sync with the Rust FFI.
const HEADER_PATH: &str = "api/native/include/azihsm_api.h";

/// clang-format executable, pinned to version 18 to match CI and the rest of
/// the repo's C/C++ formatting.
const CLANG_FORMAT_CMD: &str = "clang-format-18";

/// cbindgen version the committed header is generated with. Must match
/// `CARGO_CBINDGEN_VERSION` in `setup.rs`; cbindgen output is not stable across
/// versions, so the committed header only round-trips with this exact version.
#[cfg(not(target_os = "windows"))]
const CBINDGEN_VERSION: &str = "0.29.2";

/// Xtask to generate / verify the committed C header
#[derive(Parser)]
#[clap(about = "Generate or verify the committed cbindgen C header")]
pub struct Cbindgen {
    /// Write the regenerated header to the committed location instead of
    /// checking it
    #[clap(long)]
    pub fix: bool,

    /// Path to the clang-format executable (pinned to version 18 by default)
    #[clap(long, default_value = CLANG_FORMAT_CMD)]
    pub clang_format_executable: String,
}

impl Xtask for Cbindgen {
    #[cfg(target_os = "windows")]
    fn run(self, _ctx: XtaskCtx) -> Result<()> {
        eprintln!(
            "Skipping generation, formatting, and freshness checking of {HEADER_PATH} on Windows; \
             regenerate on Linux or WSL. Linux CI enforces header freshness."
        );
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn run(self, ctx: XtaskCtx) -> Result<()> {
        log::trace!("running cbindgen");

        let sh = Shell::new()?;

        // Both tools must be available and pinned so that local and CI
        // generation produce byte-identical output.
        let version = cmd!(sh, "cbindgen --version")
            .quiet()
            .read()
            .context("cbindgen not found. Run `cargo xtask setup` to install it.")?;
        if !version.split_whitespace().any(|t| t == CBINDGEN_VERSION) {
            bail!(
                "cbindgen {CBINDGEN_VERSION} is required to match the committed \
                 header, but found '{}'. Run `cargo xtask setup` to install the \
                 pinned version.",
                version.trim()
            );
        }

        let clang = &self.clang_format_executable;
        cmd!(sh, "{clang} --version")
            .quiet()
            .run()
            .context(format!(
                "'{clang}' not found. Install clang-format 18 (it is required to \
                 format the committed header)."
            ))?;

        let crate_dir = ctx.root.join(CRATE_DIR);
        let config = ctx.root.join(CONFIG_PATH);
        let header_path = ctx.root.join(HEADER_PATH);
        // Use the repository style explicitly when formatting stdin.
        let style_arg = format!("-style=file:{}", ctx.root.join(".clang-format").display());

        let raw = cmd!(sh, "cbindgen --config {config} {crate_dir}")
            .quiet()
            .read()
            .context("cbindgen failed to generate the header")?;
        let mut formatted = cmd!(sh, "{clang} {style_arg}")
            .stdin(raw)
            .quiet()
            .read()
            .context("clang-format failed to format the generated header")?;
        // xshell's read removes the trailing newline.
        if !formatted.ends_with('\n') {
            formatted.push('\n');
        }

        if self.fix {
            write_header(&header_path, &formatted)?;
            log::info!("wrote {}", HEADER_PATH);
            return Ok(());
        }

        check_header(&header_path, &formatted)
    }
}

/// Write the regenerated header to the committed location, creating the parent
/// directory if needed.
#[cfg(not(target_os = "windows"))]
fn write_header(header_path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = header_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(header_path, contents)
        .with_context(|| format!("failed to write {}", header_path.display()))
}

/// Compare the committed header against the freshly generated text, printing a
/// diff and failing when they differ.
#[cfg(not(target_os = "windows"))]
fn check_header(header_path: &Path, expected: &str) -> Result<()> {
    let committed = fs::read_to_string(header_path).with_context(|| {
        format!(
            "committed header {} is missing. Run `cargo xtask cbindgen --fix` \
             and commit the result.",
            HEADER_PATH
        )
    })?;

    if committed == expected {
        log::trace!("done cbindgen");
        return Ok(());
    }

    print_diff(&committed, expected, header_path);
    bail!(
        "committed header {} is out of date. Run `cargo xtask cbindgen --fix` \
         and commit the result.",
        HEADER_PATH
    );
}

/// Print a unified diff between the committed header and the expected text.
#[cfg(not(target_os = "windows"))]
fn print_diff(committed: &str, expected: &str, header_path: &Path) {
    let diff = similar::TextDiff::from_lines(committed, expected);
    let file_str = header_path.display();

    println!("--- {file_str}\t(committed)");
    println!("+++ {file_str}\t(regenerated)");

    for hunk in diff.unified_diff().context_radius(3).iter_hunks() {
        println!("{}", hunk.header().to_string().trim_end());
        for change in hunk.iter_changes() {
            let prefix = match change.tag() {
                similar::ChangeTag::Delete => "-",
                similar::ChangeTag::Insert => "+",
                similar::ChangeTag::Equal => " ",
            };
            print!("{}{}", prefix, change.value());
        }
    }
}
