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
        let mut replacement = None;
        let mut offset = 0;
        for line in file_content
            .split_inclusive('\n')
            .take(Self::COPYRIGHT_PRESENT_IN_LINES)
        {
            let line_end = offset + line.len();
            let line_without_cr = line.trim_end_matches('\r');
            if line_contains_word(line_without_cr, "Copyright")
                && line_contains_word(line_without_cr, "Microsoft")
            {
                let line_ending = if line.ends_with("\r\n") {
                    "\r\n"
                } else if line.ends_with('\n') {
                    "\n"
                } else {
                    ""
                };
                replacement = Some((offset, line_end, line_ending));
                break;
            }
            offset = line_end;
        }

        if let Some((line_start, line_end, line_ending)) = replacement {
            debug_assert!(line_end >= line_start);
            let _original_len = line_end - line_start;
            let capacity = file_content
                .len()
                .checked_add(header.len())
                .expect("capacity overflow");
            let mut updated = String::with_capacity(capacity);
            updated.push_str(&file_content[..line_start]);
            updated.push_str(&header);
            updated.push_str(line_ending);
            updated.push_str(&file_content[line_end..]);
            file_content = updated;
        } else {
            let header = format!("{header}\n");
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
            "// {}\n// Another line\nfn main() {{}}\n",
            Copyright::COPYRIGHT_HEADER_TEXT
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
        let expected = format!("// {}\nfn main() {{}}\n", Copyright::COPYRIGHT_HEADER_TEXT);
        assert_eq!(updated, expected);
    }
}
