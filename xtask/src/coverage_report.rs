// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to generate a markdown coverage report from Cobertura XML.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs;

use anyhow::Context;
use clap::Parser;
use glob::Pattern;
use quick_xml::events::Event;
use quick_xml::Reader;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to generate markdown coverage report from Cobertura XML
#[derive(Parser)]
#[clap(about = "Generate a markdown coverage report from Cobertura XML")]
pub struct CoverageReport {}

#[derive(Default, Debug, Clone)]
struct CoverageCounts {
    functions: HashMap<String, bool>, // function name -> covered
    lines: HashMap<u64, u64>,         // line number -> hits
}

impl Xtask for CoverageReport {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running coverage report generation");

        let cobertura_path = ctx
            .root
            .join("target")
            .join("reports")
            .join("cobertura_sdk.xml");

        let xml = fs::read_to_string(&cobertura_path).with_context(|| {
            format!(
                "Failed to read cobertura report at {}",
                cobertura_path.display()
            )
        })?;

        let per_file = parse_cobertura(&xml)?;

        let table = render_markdown_table(&per_file);

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

fn parse_cobertura(xml: &str) -> anyhow::Result<BTreeMap<String, CoverageCounts>> {
    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);

    let mut buf = Vec::new();
    let mut current_file: Option<String> = None;
    let mut in_function = false;
    let mut function_has_hit = false;
    let mut function_name: Option<String> = None;
    let closure_pattern = Pattern::new("*{closure#[0-9]}*")?;

    let mut per_file: BTreeMap<String, CoverageCounts> = BTreeMap::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => match e.name().as_ref() {
                b"class" => {
                    if let Some(filename) = get_attr_value(e, b"filename")? {
                        current_file = Some(filename.clone());
                        per_file.entry(filename).or_default();
                    }
                }
                b"method" => {
                    if current_file.is_some() {
                        function_name = get_attr_value(e, b"name")?;

                        // ignore closure functions
                        if !closure_pattern.matches(function_name.as_deref().unwrap_or_default()) {
                            in_function = true;
                            function_has_hit = false;
                            if let Some(entry) =
                                current_file.as_ref().and_then(|f| per_file.get_mut(f))
                            {
                                entry
                                    .functions
                                    .entry(function_name.clone().unwrap_or_default())
                                    .or_insert(false);
                            }
                        }
                    }
                }
                _ => {}
            },
            Ok(Event::End(ref e)) => match e.name().as_ref() {
                b"method" => {
                    if in_function {
                        if function_has_hit {
                            if let Some(entry) =
                                current_file.as_ref().and_then(|f| per_file.get_mut(f))
                            {
                                entry
                                    .functions
                                    .entry(function_name.clone().unwrap_or_default())
                                    .insert_entry(true);
                            }
                        }
                    }
                    in_function = false;
                    function_has_hit = false;
                }
                b"class" => {
                    current_file = None;
                }
                _ => {}
            },
            Ok(Event::Empty(ref e)) => if e.name().as_ref() == b"line" {
                if let Some(file) = current_file.as_ref() {
                    if let Some(entry) = per_file.get_mut(file) {
                        let hits = get_attr_value(e, b"hits")?
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(0);

                        let number = get_attr_value(e, b"number")?
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(0);

                        *entry.lines.entry(number).or_insert(0) += hits;

                        if in_function && hits > 0 {
                            function_has_hit = true;
                        }
                    }
                }
            },
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow::anyhow!("Failed to parse Cobertura XML: {}", e)),
            _ => {}
        }

        buf.clear();
    }

    Ok(per_file)
}

fn get_attr_value(
    e: &quick_xml::events::BytesStart<'_>,
    key: &[u8],
) -> anyhow::Result<Option<String>> {
    for attr in e.attributes() {
        let attr = attr?;
        if attr.key.as_ref() == key {
            let value = std::str::from_utf8(&attr.value)?;
            return Ok(Some(value.to_string()));
        }
    }
    Ok(None)
}

fn render_markdown_table(per_file: &BTreeMap<String, CoverageCounts>) -> String {
    let mut lines = Vec::new();
    let mut total_functions_covered = 0;
    let mut total_lines_covered = 0;
    let mut total_functions = 0;
    let mut total_lines = 0;

    lines.push("| Filename | Function Coverage | Line Coverage |".to_string());
    lines.push("| --- | --- | --- |".to_string());

    for (file, counts) in per_file {
        let functions_covered = counts
            .functions
            .values()
            .filter(|&&covered| covered)
            .count() as u64;
        let lines_covered = counts.lines.values().filter(|&&hits| hits > 0).count() as u64;

        total_functions_covered += functions_covered;
        total_lines_covered += lines_covered;
        total_functions += counts.functions.len() as u64;
        total_lines += counts.lines.len() as u64;

        lines.push(format!(
            "| {} | {} | {} |",
            file,
            format_ratio(functions_covered, counts.functions.len() as u64),
            format_ratio(lines_covered, counts.lines.len() as u64)
        ));
    }

    lines.push(format!(
        "| **Totals** | {} | {} |",
        format_ratio(total_functions_covered, total_functions),
        format_ratio(total_lines_covered, total_lines)
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
