// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to generate a markdown coverage report from JSON output of coverage xtask.

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

/// (Intended for use in Github Actions CI) Xtask to generate markdown coverage report from JSON output of coverage xtask
#[derive(Parser)]
#[clap(
    about = "(Intended for use in Github Actions CI) Generate a markdown coverage report from JSON output of coverage xtask"
)]
pub struct CoverageReport {}

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

        // Find path to azihsm_api_native object file
        let build_dir = ctx
            .root
            .join("target")
            .join("llvm-cov-target")
            .join("debug")
            .join("build");
        let mut native_obj_path = None;
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
                            native_obj_path =
                                Some(path.join("out").join("build").join("azihsm_api_native.dll"));
                        }
                        #[cfg(not(target_os = "windows"))]
                        {
                            native_obj_path = Some(
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

        // set LLVM_COV_FLAGS to include azihsm_api_native object file in coverage reports
        if let Some(native_obj_path) = native_obj_path {
            if native_obj_path.is_file() {
                let path_str = native_obj_path.to_string_lossy();
                let new_flags = match std::env::var("LLVM_COV_FLAGS") {
                    Ok(existing) if !existing.trim().is_empty() => {
                        format!("{existing} -object {path_str}")
                    }
                    _ => format!("-object {path_str}"),
                };
                sh.set_var("LLVM_COV_FLAGS", new_flags);
            } else {
                log::warn!("Could not find azihsm_api_native object at expected path: {}. Coverage reports may be incomplete.", native_obj_path.display());
            }
        } else {
            log::warn!("Could not find cmake build directory or azihsm_api_native object. Coverage reports may be incomplete.");
        }

        // append /target/debug/libazihsm_api_native.so to LLVM_COV_FLAGS
        let additional_libs = ["./target/debug/libazihsm_api_native.so"];
        for lib in &additional_libs {
            if std::path::Path::new(lib).exists() {
                let new_flags = match std::env::var("LLVM_COV_FLAGS") {
                    Ok(existing) if !existing.trim().is_empty() => {
                        format!("{existing} -object {lib}")
                    }
                    _ => format!("-object {lib}"),
                };
                sh.set_var("LLVM_COV_FLAGS", new_flags);
            } else {
                log::warn!("Could not find library at expected path: {}. Coverage reports may be incomplete.", lib);
            }
        }

        // Generate cobertura report
        log::info!("Generating cobertura report");
        cmd!(
            sh,
            "cargo llvm-cov report --cobertura --output-path ./target/reports/cobertura_sdk.xml --ignore-filename-regex xtask*"
        ).run()?;

        // Generate json report
        log::info!("Generating json report");
        cmd!(
            sh,
            "cargo llvm-cov report --json --summary-only --output-path ./target/reports/sdk-cov.json --ignore-filename-regex xtask*"
        ).run()?;

        // Generate HTML report
        log::info!("Generating HTML report");
        cmd!(sh, "cargo llvm-cov report --html --output-dir ./target/reports/sdk-cov/ --ignore-filename-regex xtask*").run()?;

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

        println!("{}", table);

        // Write to GITHUB_STEP_SUMMARY environment variable
        if let Ok(summary_path) = std::env::var("GITHUB_STEP_SUMMARY") {
            let mut file = OpenOptions::new().append(true).open(&summary_path)?;
            file.write_all(table.as_bytes())?;
            log::trace!("Report written to GITHUB_STEP_SUMMARY");
        } else {
            // If not in GitHub Actions, just print to stdout
            //println!("{}", table);
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
