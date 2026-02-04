// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
    const COPYRIGHT_HEADER_LINE1: &str = "Copyright (c) Microsoft Corporation.";
    const COPYRIGHT_HEADER_LINE2: &str = "Licensed under the MIT License.";

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
        let lines: Vec<_> = f.lines().take(Self::COPYRIGHT_PRESENT_IN_LINES).collect();

        // Check if the new two-line format is present
        if lines.len() >= 2 {
            if let (Ok(line1), Ok(line2)) = (&lines[0], &lines[1]) {
                if line1.contains(Self::COPYRIGHT_HEADER_LINE1) 
                    && line2.contains(Self::COPYRIGHT_HEADER_LINE2) {
                    return Ok(());
                }
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

        let header_line1 = format!("{} {}", prefix, Self::COPYRIGHT_HEADER_LINE1);
        let header_line2 = format!("{} {}", prefix, Self::COPYRIGHT_HEADER_LINE2);
        
        // Look for existing copyright header to replace
        let mut replacement = None;
        let mut offset = 0;
        let mut lines_to_replace = 0;
        
        for (idx, line) in file_content
            .split_inclusive('\n')
            .take(Self::COPYRIGHT_PRESENT_IN_LINES)
            .enumerate()
        {
            let line_end = offset + line.len();
            let line_without_cr = line.trim_end_matches('\r');
            
            if line_contains_word(line_without_cr, "Copyright")
                && line_contains_word(line_without_cr, "Microsoft")
            {
                // Found copyright line, mark it for replacement
                if replacement.is_none() {
                    let line_ending = if line.ends_with("\r\n") {
                        "\r\n"
                    } else if line.ends_with('\n') {
                        "\n"
                    } else {
                        ""
                    };
                    replacement = Some((offset, line_end, line_ending));
                    lines_to_replace = 1;
                } else {
                    // Second copyright-related line, extend replacement range
                    lines_to_replace = 2;
                    replacement = Some((replacement.unwrap().0, line_end, replacement.unwrap().2));
                }
            } else if replacement.is_some() && idx < 2 {
                // We found copyright on first line, check if second line is license-related
                if line_contains_word(line_without_cr, "License") 
                    || line_contains_word(line_without_cr, "rights")
                    || line_contains_word(line_without_cr, "reserved")
                {
                    lines_to_replace = 2;
                    replacement = Some((replacement.unwrap().0, line_end, replacement.unwrap().2));
                }
                break;
            }
            offset = line_end;
        }

        if let Some((line_start, line_end, line_ending)) = replacement {
            debug_assert!(line_end >= line_start);
            let capacity = file_content
                .len()
                .checked_add(header_line1.len() + header_line2.len() + 2)
                .expect("capacity overflow");
            let mut updated = String::with_capacity(capacity);
            updated.push_str(&file_content[..line_start]);
            updated.push_str(&header_line1);
            updated.push_str(line_ending);
            updated.push_str(&header_line2);
            updated.push_str(line_ending);
            updated.push_str(&file_content[line_end..]);
            file_content = updated;
        } else {
            // No copyright found, insert at beginning
            let header = format!("{header_line1}\n{header_line2}\n");
            file_content.insert_str(0, &header);
        }

        std::fs::write(path, file_content)?;
        Ok(())
    }
}

fn line_contains_word(line: &str, word: &str) -> bool {
    line.split(|ch: char| !ch.is_alphanumeric())
        .any(|token| token.eq_ignore_ascii_case(word))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    use super::Copyright;

    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn new(ext: &str) -> Self {
            Self {
                path: temp_path(ext),
            }
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn temp_path(ext: &str) -> PathBuf {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch");
        let timestamp = format!("{}_{}", duration.as_secs(), duration.subsec_nanos());
        let mut path = std::env::temp_dir();
        path.push(format!(
            "xtask_copyright_{timestamp}_{:?}_{}.{}",
            std::thread::current().id(),
            std::process::id(),
            ext
        ));
        path
    }

    #[test]
    fn fix_copyright_replaces_existing_header() {
        let temp = TempFile::new("rs");
        let contents = "// Copyright 2024 Microsoft\n// Another line\nfn main() {}\n";
        std::fs::write(&temp.path, contents).expect("write temp file");

        Copyright::fix_copyright(&temp.path).expect("fix copyright");

        let updated = std::fs::read_to_string(&temp.path).expect("read temp file");
        let expected = format!(
            "// {}\n// {}\n// Another line\nfn main() {{}}\n",
            Copyright::COPYRIGHT_HEADER_LINE1,
            Copyright::COPYRIGHT_HEADER_LINE2
        );
        assert_eq!(updated, expected);
    }

    #[test]
    fn fix_copyright_inserts_when_missing() {
        let temp = TempFile::new("rs");
        let contents = "fn main() {}\n";
        std::fs::write(&temp.path, contents).expect("write temp file");

        Copyright::fix_copyright(&temp.path).expect("fix copyright");

        let updated = std::fs::read_to_string(&temp.path).expect("read temp file");
        let expected = format!(
            "// {}\n// {}\nfn main() {{}}\n",
            Copyright::COPYRIGHT_HEADER_LINE1,
            Copyright::COPYRIGHT_HEADER_LINE2
        );
        assert_eq!(updated, expected);
    }
}
