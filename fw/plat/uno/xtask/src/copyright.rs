// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Copyright header check for the uno firmware workspace.

use std::fs;

use anyhow::bail;
use clap::Parser;
use walkdir::WalkDir;

use crate::Xtask;
use crate::XtaskCtx;

const COPYRIGHT_HEADER: &str = "// Copyright (c) Microsoft Corporation.";

/// Check (or fix) copyright headers on Rust sources in the uno firmware workspace.
#[derive(Parser)]
#[clap(about = "Check copyright headers on Rust sources")]
pub struct Copyright {
    /// Prepend the copyright header to any file that is missing it.
    #[clap(long)]
    pub fix: bool,
}

impl Xtask for Copyright {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        let mut missing = Vec::new();

        for entry in WalkDir::new(&ctx.root)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                // Skip build outputs, VCS, and third-party crates that ship under
                // their own (non-Microsoft) license headers.
                !(e.file_type().is_dir()
                    && (name == "target"
                        || name == ".git"
                        || name == "systemrdl"
                        || name == "static_ref"
                        || name == "static_init"))
            })
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }

            let content = fs::read_to_string(path)?;
            let first_line = content.lines().next().unwrap_or("");
            if first_line != COPYRIGHT_HEADER {
                if self.fix {
                    log::info!("Fixing: {}", path.display());
                    let new_content = format!("{COPYRIGHT_HEADER}\n{content}");
                    fs::write(path, new_content)?;
                } else {
                    missing.push(path.to_path_buf());
                }
            }
        }

        if !self.fix && !missing.is_empty() {
            for path in &missing {
                log::error!("Missing copyright header: {}", path.display());
            }
            bail!(
                "{} file(s) missing copyright header. Run with --fix to add.",
                missing.len()
            );
        }

        log::info!("Copyright check complete.");
        Ok(())
    }
}
