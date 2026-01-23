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

        let header = format!("{} {}", prefix, Self::COPYRIGHT_HEADER_TEXT);
        let mut lines: Vec<String> = file_content
            .split_inclusive('\n')
            .map(str::to_string)
            .collect();
        let mut replaced = false;

        for line in lines.iter_mut().take(Self::COPYRIGHT_PRESENT_IN_LINES) {
            if line.contains("Copyright") && line.contains("Microsoft") {
                let line_ending = if line.ends_with("\r\n") {
                    "\r\n"
                } else if line.ends_with('\n') {
                    "\n"
                } else {
                    ""
                };
                *line = format!("{header}{line_ending}");
                replaced = true;
                break;
            }
        }

        if replaced {
            file_content = lines.concat();
        } else {
            let header = format!("{header}\n");
            file_content.insert_str(0, header.as_str());
        }

        std::fs::write(path, file_content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::Copyright;

    fn temp_path(ext: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "xtask_copyright_{nanos}_{}.{}",
            std::process::id(),
            ext
        ));
        path
    }

    #[test]
    fn fix_copyright_replaces_existing_header() {
        let path = temp_path("rs");
        let contents = "// Copyright 2024 Microsoft\n// Another line\nfn main() {}\n";
        std::fs::write(&path, contents).expect("write temp file");

        Copyright::fix_copyright(&path).expect("fix copyright");

        let updated = std::fs::read_to_string(&path).expect("read temp file");
        let expected = format!(
            "// {}\n// Another line\nfn main() {{}}\n",
            Copyright::COPYRIGHT_HEADER_TEXT
        );
        std::fs::remove_file(&path).expect("remove temp file");
        assert_eq!(updated, expected);
    }

    #[test]
    fn fix_copyright_inserts_when_missing() {
        let path = temp_path("rs");
        let contents = "fn main() {}\n";
        std::fs::write(&path, contents).expect("write temp file");

        Copyright::fix_copyright(&path).expect("fix copyright");

        let updated = std::fs::read_to_string(&path).expect("read temp file");
        let expected = format!("// {}\nfn main() {{}}\n", Copyright::COPYRIGHT_HEADER_TEXT);
        std::fs::remove_file(&path).expect("remove temp file");
        assert_eq!(updated, expected);
    }
}
