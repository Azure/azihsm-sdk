// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to generate a markdown coverage report from Cobertura XML.

use std::collections::BTreeMap;
use std::fs;
use std::path;

use anyhow::Context;
use clap::Parser;
use jzon::parse;
use jzon::JsonValue;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to generate markdown coverage report from Cobertura XML
#[derive(Parser)]
#[clap(about = "Generate a markdown coverage report from Cobertura XML")]
pub struct CoverageReport {}

#[derive(Default, Debug, Clone)]
struct LineSummary {
    count: u64,
    covered: u64,
    percent: f64,
}

impl Xtask for CoverageReport {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running coverage report generation");

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
                                            summary.percent = lines_obj
                                                .get("percent")
                                                .and_then(|v| v.as_f64())
                                                .unwrap_or(0.0);
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
            fs::write(&summary_path, &table)?;
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
