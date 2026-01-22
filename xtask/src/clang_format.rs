// Copyright (C) Microsoft Corporation. All rights reserved.

// Adopted from https://github.com/Sarcasm/run-clang-format python script

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run clang-format on C/C++ files

use std::collections::HashSet;
use std::fs;
use std::io::*;
use std::path::*;
use std::process::Command;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use is_terminal::IsTerminal;

use crate::Xtask;
use crate::XtaskCtx;

const DEFAULT_CLANG_FORMAT_IGNORE: &str = ".clang-format-ignore";

/// Xtask to run clang-format on C/C++ files
#[derive(Parser)]
#[clap(about = "Run clang-format on C/C++ files")]
pub struct ClangFormat {
    /// Path to the clang-format executable (pinned to version 18 by default)
    #[clap(long, default_value = "clang-format-18")]
    pub clang_format_executable: String,

    /// Comma separated list of file extensions
    #[clap(long, default_value = "c,h,C,H,cpp,hpp,cc,hh,c++,h++,cxx,hxx")]
    pub extensions: String,

    /// Run recursively over directories
    #[clap(short, long)]
    pub recursive: bool,

    /// Just print the list of files
    #[clap(short = 'd', long)]
    pub dry_run: bool,

    /// Format file instead of printing differences
    #[clap(short, long)]
    pub in_place: bool,

    /// Disable output, useful for the exit code
    #[clap(short, long)]
    pub quiet: bool,

    /// Show colored diff
    #[clap(long, default_value = "auto", value_parser = ["auto", "always", "never"])]
    pub color: String,

    /// Exclude paths matching the given glob-like pattern(s) from recursive search
    #[clap(short, long)]
    pub exclude: Vec<String>,

    /// Files or directories to format
    #[clap(required = true)]
    pub files: Vec<PathBuf>,
}

impl Xtask for ClangFormat {
    fn run(self, _ctx: XtaskCtx) -> Result<()> {
        log::trace!("running clang-format");

        // Capture output of `clang-format --version`
        let version_output = Command::new(&self.clang_format_executable)
            .arg("--version")
            .output();

        if let Ok(ref output) = version_output {
            println!("{}", String::from_utf8_lossy(&output.stdout).trim());
        }

        // Check clang-format is available
        version_output
            .context(format!(
                "Failed to run '{}'. Is it installed?",
                self.clang_format_executable
            ))?
            .status
            .success()
            .then_some(())
            .context(format!(
                "Command '{}' returned non-zero exit status",
                self.clang_format_executable
            ))?;

        // Determine color settings
        let colored = match self.color.as_str() {
            "always" => true,
            "never" => false,
            _ => std::io::stdout().is_terminal(),
        };

        // Load excludes from .clang-format-ignore file and command line
        let mut excludes = load_excludes_from_file(DEFAULT_CLANG_FORMAT_IGNORE)?;
        for pattern in &self.exclude {
            excludes.push(glob::Pattern::new(pattern)?);
        }

        // Parse extensions and list files to format
        let extensions: HashSet<String> = self
            .extensions
            .split(',')
            .map(str::trim)
            .map(String::from)
            .collect();
        let files = list_files(&self.files, self.recursive, &extensions, &excludes)?;

        if files.is_empty() {
            log::info!("No files to format");
            return Ok(());
        }

        // Process files
        let (has_diff, has_error) = files.iter().fold((false, false), |(diff, error), file| {
            match process_file(
                file,
                &self.clang_format_executable,
                self.in_place,
                self.dry_run,
                self.quiet,
                colored,
            ) {
                Ok(has_changes) => (diff || has_changes, error),
                Err(e) => {
                    let prefix = if colored {
                        "\x1b[1m\x1b[31merror:\x1b[0m"
                    } else {
                        "error:"
                    };
                    eprintln!("{} {}", prefix, e);
                    (diff, true)
                }
            }
        });

        log::trace!("done clang-format");

        if has_error {
            bail!("clang-format encountered errors");
        }

        if has_diff {
            bail!("clang-format found formatting differences");
        }

        Ok(())
    }
}

/// Load exclude patterns from a file
///
/// # Arguments
/// * `path` - Path to the file containing exclude patterns
///
/// # Returns
/// A vector of glob patterns loaded from the file
fn load_excludes_from_file(path: &str) -> Result<Vec<glob::Pattern>> {
    let mut excludes = Vec::new();

    if let Ok(file) = fs::File::open(path) {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                excludes.push(glob::Pattern::new(trimmed)?);
            }
        }
    }

    Ok(excludes)
}

/// List files to format based on paths, extensions, and exclude patterns
///
/// # Arguments
/// * `paths` - Paths to search for files
/// * `recursive` - Whether to search recursively
/// * `extensions` - Set of file extensions to include
/// * `excludes` - Glob patterns to exclude
///
/// # Returns
/// A vector of file paths to format
fn list_files(
    paths: &[PathBuf],
    recursive: bool,
    extensions: &HashSet<String>,
    excludes: &[glob::Pattern],
) -> Result<Vec<PathBuf>> {
    let mut result = HashSet::new();

    for path in paths {
        if path.is_file() {
            result.insert(path.clone());
            continue;
        }
        let pattern_suffix: &str = if recursive { "/**/*" } else { "/*" };
        for ext in extensions {
            let pattern = format!("{}{}.{}", path.display(), pattern_suffix, ext);
            for entry in glob::glob(&pattern)? {
                let file_path = entry?;
                if !is_excluded(&file_path, excludes) {
                    result.insert(file_path);
                }
            }
        }
    }

    Ok(result.into_iter().collect())
}

/// Check if a path is excluded by any of the patterns
///
/// # Arguments
/// * `path` - Path to check
/// * `excludes` - Glob patterns to match against
///
/// # Returns
/// `true` if the path matches any exclude pattern, `false` otherwise
fn is_excluded(path: &Path, excludes: &[glob::Pattern]) -> bool {
    let path_str = path.to_string_lossy();
    let path_normalized = path_str.strip_prefix("./").unwrap_or(&path_str);

    excludes
        .iter()
        .any(|pattern| pattern.matches(path_normalized))
}

/// Process a file with clang-format
///
/// # Arguments
/// * `file` - Path to the file to format
/// * `clang_format_executable` - Path to the clang-format executable
/// * `in_place` - Whether to format the file in place
/// * `dry_run` - Whether to only print commands without executing
/// * `quiet` - Whether to suppress output
/// * `colored` - Whether to use colored output
///
/// # Returns
/// `true` if the file has formatting differences, `false` otherwise
#[allow(clippy::fn_params_excessive_bools)]
fn process_file(
    file: &Path,
    clang_format_executable: &str,
    in_place: bool,
    dry_run: bool,
    quiet: bool,
    colored: bool,
) -> Result<bool> {
    if dry_run {
        println!(
            "{} {}{}",
            clang_format_executable,
            if in_place { "-i " } else { "" },
            file.display()
        );
        return Ok(false);
    }

    let mut cmd = Command::new(clang_format_executable);
    if in_place {
        cmd.arg("-i");
    }
    cmd.arg(file);

    if in_place {
        cmd.status().context("Failed to execute clang-format")?;
        return Ok(false);
    }

    let original = fs::read_to_string(file).context("Failed to read file")?;
    let output = cmd.output().context("Failed to execute clang-format")?;
    if !output.status.success() {
        bail!(
            "clang-format failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let formatted = String::from_utf8_lossy(&output.stdout);
    if original != formatted {
        if !quiet {
            print_diff(&original, &formatted, file, colored);
        }
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Print the difference between original and formatted content
///
/// # Arguments
/// * `original` - Original file content
/// * `formatted` - Formatted file content
/// * `file` - Path to the file being formatted
/// * `colored` - Whether to use colored output
fn print_diff(original: &str, formatted: &str, file: &Path, colored: bool) {
    let diff = similar::TextDiff::from_lines(original, formatted);
    let file_str = file.display();

    let (bold_start, bold_end, cyan, red, green, reset) = if colored {
        (
            "\x1b[1m", "\x1b[0m", "\x1b[36m", "\x1b[31m", "\x1b[32m", "\x1b[0m",
        )
    } else {
        ("", "", "", "", "", "")
    };

    println!("{}--- {}\t(original){}", bold_start, file_str, bold_end);
    println!("{}+++ {}\t(reformatted){}", bold_start, file_str, bold_end);

    for hunk in diff.unified_diff().context_radius(3).iter_hunks() {
        println!("{}{}{}", cyan, hunk.header().to_string().trim_end(), reset);
        for change in hunk.iter_changes() {
            let (prefix, color) = match change.tag() {
                similar::ChangeTag::Delete => ("-", red),
                similar::ChangeTag::Insert => ("+", green),
                similar::ChangeTag::Equal => (" ", ""),
            };
            print!("{}{}{}{}", color, prefix, change.value(), reset);
        }
    }
}
