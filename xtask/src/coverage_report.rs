// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to generate a cobertura XML, JSON, HTML, and markdown coverage report from output of coverage xtask.

use std::collections::BTreeMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path;

use anyhow::Context;
use clap::Parser;
use jzon::parse;
use jzon::JsonValue;
use xshell::cmd;

use crate::Xtask;
use crate::XtaskCtx;

/// (Intended for use in GitHub Actions CI) Xtask to generate a cobertura XML, JSON, HTML, and markdown coverage report from output of coverage xtask
#[derive(Parser)]
#[clap(
    about = "(Intended for use in GitHub Actions CI) Generate a cobertura XML, JSON, HTML, and markdown coverage report from output of coverage xtask"
)]
pub struct CoverageReport {
    /// Do not append default build location of azihsm_api_native object file to LLVM_COV_FLAGS
    #[clap(long)]
    pub no_default_native: bool,

    /// Additional paths to object files to append to LLVM_COV_FLAGS
    #[clap(long)]
    pub additional_obj_paths: Vec<String>,
}

#[derive(Default, Debug, Clone)]
struct LineSummary {
    count: u64,
    covered: u64,
}

impl Xtask for CoverageReport {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running coverage report generation");

        let sh = xshell::Shell::new()?;

        // Check for/create reports directory
        let reports_dir = ctx.root.join("target").join("reports");
        if !reports_dir.exists() {
            log::info!("Creating reports directory at {}", reports_dir.display());
            std::fs::create_dir_all(&reports_dir)?;
        }

        let build_dir = ctx
            .root
            .join("target")
            .join("llvm-cov-target")
            .join("debug")
            .join("build");
        let mut native_obj_path = None;

        if !self.no_default_native {
            find_native_obj_path(build_dir, &mut native_obj_path)?;
        }

        // collect all object paths to append to LLVM_COV_FLAGS
        let mut all_obj_paths: Vec<path::PathBuf> = self
            .additional_obj_paths
            .iter()
            .map(path::PathBuf::from)
            .collect();
        if let Some(native_obj_path) = native_obj_path {
            all_obj_paths.push(native_obj_path);
        }

        // generate string to append to LLVM_COV_FLAGS
        let mut new_flags = String::new();
        for obj_path in &all_obj_paths {
            if obj_path.is_file() {
                new_flags.push_str(&format!("-object {} ", obj_path.display()));
            } else {
                return Err(anyhow::anyhow!(
                    "Object file path does not exist: {}. Check that build artifacts are present.",
                    obj_path.display()
                ));
            }
        }

        // append string to LLVM_COV_FLAGS env var
        if !new_flags.trim().is_empty() {
            let new_flags = match std::env::var("LLVM_COV_FLAGS") {
                Ok(existing) if !existing.trim().is_empty() => {
                    format!("{} {}", existing, new_flags)
                }
                _ => new_flags,
            };
            sh.set_var("LLVM_COV_FLAGS", new_flags);
        }

        // Generate cobertura report
        log::info!("Generating cobertura report");
        cmd!(
            sh,
            "cargo llvm-cov report --cobertura --output-path ./target/reports/cobertura_sdk.xml --ignore-filename-regex xtask[/\\\\]"
        ).run()?;

        // Generate json report
        log::info!("Generating json report");
        cmd!(
            sh,
            "cargo llvm-cov report --json --summary-only --output-path ./target/reports/sdk-cov.json --ignore-filename-regex xtask[/\\\\]"
        ).run()?;

        // Generate HTML report
        log::info!("Generating HTML report");
        cmd!(sh, "cargo llvm-cov report --html --output-dir ./target/reports/sdk-cov/ --ignore-filename-regex xtask[/\\\\]").run()?;

        let json_path = ctx.root.join("target").join("reports").join("sdk-cov.json");

        let json_string = fs::read_to_string(&json_path)
            .with_context(|| format!("Failed to read json report at {}", json_path.display()))?;

        let json_value = parse(&json_string)?;

        let mut line_summaries: BTreeMap<String, LineSummary> = BTreeMap::new();

        // Navigate to data array
        if let JsonValue::Object(obj) = &json_value {
            if let Some(JsonValue::Array(data_arr)) = obj.get("data") {
                // Iterate through data items
                for data_item in data_arr {
                    if let JsonValue::Object(data_obj) = data_item {
                        if let Some(JsonValue::Array(files)) = data_obj.get("files") {
                            // Process each file
                            for file in files {
                                if let JsonValue::Object(file_obj) = file {
                                    // Get filename
                                    let Some(filename) =
                                        file_obj.get("filename").and_then(|v| v.as_str())
                                    else {
                                        log::warn!("File entry missing 'filename' field");
                                        continue;
                                    };

                                    // strip repo root prefix from filename if present
                                    let filename = filename
                                        .strip_prefix(&*ctx.root.to_string_lossy())
                                        .unwrap_or(filename);

                                    // strip leading slash if present
                                    let filename = filename
                                        .strip_prefix(path::MAIN_SEPARATOR)
                                        .unwrap_or(filename);

                                    // Extract summary.lines data
                                    let mut summary = LineSummary::default();
                                    if let Some(JsonValue::Object(summary_obj)) =
                                        file_obj.get("summary")
                                    {
                                        if let Some(JsonValue::Object(lines_obj)) =
                                            summary_obj.get("lines")
                                        {
                                            summary.count = lines_obj
                                                .get("count")
                                                .and_then(|v| v.as_u64())
                                                .unwrap_or(0);
                                            summary.covered = lines_obj
                                                .get("covered")
                                                .and_then(|v| v.as_u64())
                                                .unwrap_or(0);
                                        }
                                    }

                                    line_summaries.insert(filename.to_string(), summary);
                                }
                            }
                        }
                    }
                }
            } else {
                return Err(anyhow::anyhow!(
                    "JSON report does not contain 'data' field or it is not an array"
                ));
            }
        } else {
            return Err(anyhow::anyhow!("Expected JSON report to be an object"));
        }

        let table = render_markdown_table(line_summaries);

        // Write to GITHUB_STEP_SUMMARY environment variable
        if let Ok(summary_path) = std::env::var("GITHUB_STEP_SUMMARY") {
            let mut file = OpenOptions::new().append(true).open(&summary_path)?;
            file.write_all(table.as_bytes())?;
            log::trace!("Report written to GITHUB_STEP_SUMMARY");
        } else {
            // If not in GitHub Actions, just print to stdout
            println!("{}", table);
        }

        Ok(())
    }
}

fn render_markdown_table(line_summaries: BTreeMap<String, LineSummary>) -> String {
    let mut lines = Vec::new();
    let mut total_lines_covered = 0;
    let mut total_lines_count = 0;

    lines.push("# Code Coverage\n".to_string());
    lines.push("| Filename | Line Coverage |".to_string());
    lines.push("| --- | --- |".to_string());

    for (file, summary) in line_summaries {
        let lines_covered = summary.covered;
        let lines_count = summary.count;

        total_lines_covered += lines_covered;
        total_lines_count += lines_count;

        lines.push(format!(
            "| {} | {} |",
            file,
            format_ratio(lines_covered, lines_count)
        ));
    }

    lines.push(format!(
        "| **Totals** | {} |",
        format_ratio(total_lines_covered, total_lines_count)
    ));

    lines.join("\n")
}

fn format_ratio(covered: u64, total: u64) -> String {
    if total == 0 {
        return "0.00% (0/0)".to_string();
    }
    let pct = (covered as f64) * 100.0 / (total as f64);
    format!("{:.2}% ({}/{})", pct, covered, total)
}

fn find_native_obj_path(
    build_dir: path::PathBuf,
    native_obj_path: &mut Option<path::PathBuf>,
) -> anyhow::Result<()> {
    // Find path to azihsm_api_native object file
    *native_obj_path = None;
    if build_dir.exists() {
        for entry in std::fs::read_dir(&build_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir()
                && path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .map(|s| s.starts_with("azihsm_api_tests-"))
                    .unwrap_or(false)
            {
                // check if directory contains 'out' subdirectory to see if it's the cmake build directory
                if path.join("out").is_dir() {
                    log::info!("Found cmake build directory at: {}", path.display());
                    #[cfg(target_os = "windows")]
                    {
                        *native_obj_path =
                            Some(path.join("out").join("build").join("azihsm_api_native.dll"));
                    }
                    #[cfg(not(target_os = "windows"))]
                    {
                        *native_obj_path = Some(
                            path.join("out")
                                .join("build")
                                .join("libazihsm_api_native.so"),
                        );
                    }
                    break;
                }
            }
        }
    } else {
        log::warn!(
            "Cargo build-script directory not found at expected path: {}. Coverage reports may be incomplete.",
            build_dir.display()
        );
    }

    Ok(())
}
