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
    const COPYRIGHT_PRESENT_IN_LINES: usize = 4;
    const COPYRIGHT_HEADER_TEXT: &str = "Copyright (c) Microsoft Corporation.\nLicensed under the MIT License.";

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
        let lines: Vec<_> = f.lines()
            .take(Self::COPYRIGHT_PRESENT_IN_LINES)
            .collect::<Result<_, _>>()?;

        // Check if the copyright header is present (both lines)
        let header_parts: Vec<&str> = Self::COPYRIGHT_HEADER_TEXT.split('\n').collect();
        let mut found_parts = 0;
        
        for line in &lines {
            for part in &header_parts {
                if line.contains(part) {
                    found_parts += 1;
                }
            }
        }

        // All parts of the header must be present
        if found_parts >= header_parts.len() {
            return Ok(());
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

        // Split the header text into lines and add prefix to each
        let header_lines: Vec<String> = Self::COPYRIGHT_HEADER_TEXT
            .split('\n')
            .map(|line| format!("{} {}", prefix, line))
            .collect();
        let header = header_lines.join("\n");

        // Find Microsoft copyright header to replace (may span multiple lines)
        let mut replacement = None;
        let mut offset = 0;
        let mut found_copyright_line = None;
        
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
                found_copyright_line = Some((idx, offset, line_end));
                break;
            }
            offset = line_end;
        }

        if let Some((_start_idx, start_offset, mut end_offset)) = found_copyright_line {
            // Determine line ending style
            let line_ending = if file_content[start_offset..end_offset].ends_with("\r\n") {
                "\r\n"
            } else if file_content[start_offset..end_offset].ends_with('\n') {
                "\n"
            } else {
                ""
            };

            // Check if the next line(s) contain "Licensed" or "All rights reserved" 
            // to replace them as part of the old header
            let mut lines_iter = file_content[end_offset..]
                .split_inclusive('\n')
                .take(2);
            
            while let Some(next_line) = lines_iter.next() {
                let next_line_trimmed = next_line.trim_end_matches('\r').trim_end_matches('\n').trim();
                if next_line_trimmed.starts_with(prefix) {
                    let content = next_line_trimmed.trim_start_matches(prefix).trim();
                    if content.contains("Licensed") 
                        || content.contains("All rights reserved")
                        || content.is_empty()
                    {
                        end_offset += next_line.len();
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }

            replacement = Some((start_offset, end_offset, line_ending));
        }

        if let Some((line_start, line_end, line_ending)) = replacement {
            debug_assert!(line_end >= line_start);
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
        let header_lines: Vec<String> = Copyright::COPYRIGHT_HEADER_TEXT
            .split('\n')
            .map(|line| format!("// {}", line))
            .collect();
        let expected = format!(
            "{}\n// Another line\nfn main() {{}}\n",
            header_lines.join("\n")
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
        let header_lines: Vec<String> = Copyright::COPYRIGHT_HEADER_TEXT
            .split('\n')
            .map(|line| format!("// {}", line))
            .collect();
        let expected = format!("{}\nfn main() {{}}\n", header_lines.join("\n"));
        assert_eq!(updated, expected);
    }
}
