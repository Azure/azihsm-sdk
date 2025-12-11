// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run various repo-specific copyright checks

use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;

use clap::Parser;

use crate::common;
use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run various repo-specific copyright checks
#[derive(Parser)]
#[clap(about = "Run various copyright checks")]
pub struct Copyright {
    /// Attempt to fix any missing copyright header issues
    #[clap(long)]
    pub fix: bool,
}

impl Xtask for Copyright {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running copyright");

        // Get all files tracked by git
        let files = common::git_ls_files()?;

        // Check each file for copyright header
        for path in files {
            if let Err(e) = Copyright::check_copyright(&path, self.fix) {
                log::error!("Error checking copyright for {}: {}", path.display(), e);
                if !self.fix {
                    return Err(e);
                }
            }
        }

        log::trace!("done copyright");
        Ok(())
    }
}

impl Copyright {
    const COPYRIGHT_PRESENT_IN_LINES: usize = 3;
    const COPYRIGHT_HEADER_TEXT: &str = "Copyright (C) Microsoft Corporation. All rights reserved.";

    fn check_copyright(path: &Path, fix: bool) -> anyhow::Result<()> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();

        if !matches!(
            ext,
            "rs" | "toml" | "h" | "c" | "cpp" | "sh" | "py" | "ps1" | "psm1" | "txt"
        ) {
            return Ok(());
        }

        let f = BufReader::new(File::open(path)?);
        let lines = f.lines().take(Self::COPYRIGHT_PRESENT_IN_LINES);

        for line in lines {
            let line = line?;
            if line.contains(Self::COPYRIGHT_HEADER_TEXT) {
                return Ok(());
            }
        }

        if fix {
            Self::fix_copyright(path)
        } else {
            // Error
            Err(anyhow::anyhow!(
                "Copyright header not found in {}",
                path.display()
            ))?
        }
    }

    fn fix_copyright(path: &Path) -> anyhow::Result<()> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();

        let mut file_content = std::fs::read_to_string(path)?;

        let prefix = match ext {
            "rs" | "h" | "c" | "cpp" => "//",
            "toml" | "sh" | "py" | "ps1" | "psm1" | "txt" => "#",
            _ => Err(anyhow::anyhow!(
                "Unsupported file type for copyright fix: {}",
                ext
            ))?,
        };

        let header = format!("{} {}\n", prefix, Self::COPYRIGHT_HEADER_TEXT);
        file_content.insert_str(0, header.as_str());

        std::fs::write(path, file_content)?;
        Ok(())
    }
}
