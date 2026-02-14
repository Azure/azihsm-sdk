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
    lines: HashMap<u64, u64>,      // line number -> hits
    regions: HashMap<String, (u64, u64)>,   // region identifier -> (covered, total)
}

impl CoverageCounts {
    fn add(&mut self, other: CoverageCounts) {
        for (k, v) in other.functions {
            let entry = self.functions.entry(k).or_insert(false);
            *entry |= v;
        }
        for (k, v) in other.lines {
            let entry = self.lines.entry(k).or_insert(0);
            *entry += v;
        }
        for (k, v) in other.regions {
            let entry = self.regions.entry(k).or_insert((0, 0));
            entry.0 += v.0;
            entry.1 += v.1;
        }
    }
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
    let mut in_method = false;
    let mut method_has_hit = false;
    let mut method_entry;

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
                        in_method = true;
                        method_has_hit = false;
                        if let Some(entry) = current_file.as_ref().and_then(|f| per_file.get_mut(f))
                        {
                            let name = get_attr_value(e, b"name")?.unwrap_or_default();

                            method_entry = entry.functions.entry(name);
                            method_entry.or_insert(false);
                        }
                    }
                }
                b"line" => {
                    if let Some(file) = current_file.as_ref() {
                        if let Some(entry) = per_file.get_mut(file) {
                            let hits = get_attr_value(e, b"hits")?
                                .and_then(|v| v.parse::<u64>().ok())
                                .unwrap_or(0);

                            let number = get_attr_value(e, b"number")?
                                .and_then(|v| v.parse::<u64>().ok())
                                .unwrap_or(0);

                            *entry.lines.entry(number).or_insert(0) += hits;

                            if in_method && hits > 0 {
                                method_has_hit = true;
                            }
                        }
                    }
                }
                _ => {}
            },
            Ok(Event::End(ref e)) => match e.name().as_ref() {
                b"method" => {
                    if in_method {
                        if let Some(file) = current_file.as_ref() {
                            if let Some(entry) = per_file.get_mut(file) {
                                if method_has_hit {
                                    method_entry.or_insert(true);
                                }
                            }
                        }
                        in_method = false;
                        method_has_hit = false;
                    }
                }
                b"class" => {
                    current_file = None;
                }
                _ => {}
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

fn parse_condition_coverage(value: &str) -> Option<(u64, u64)> {
    let start = value.find('(')? + 1;
    let end = value.find(')')?;
    let inner = value.get(start..end)?;
    let mut parts = inner.split('/');
    let covered = parts.next()?.trim().parse::<u64>().ok()?;
    let total = parts.next()?.trim().parse::<u64>().ok()?;
    Some((covered, total))
}

fn render_markdown_table(per_file: &BTreeMap<String, CoverageCounts>) -> String {
    let mut totals = CoverageCounts::default();
    let mut lines = Vec::new();

    lines.push("| Filename | Function Coverage | Line Coverage | Region Coverage |".to_string());
    lines.push("| --- | --- | --- | --- |".to_string());

    for (file, counts) in per_file {
        let functions_covered = counts.functions.values().filter(|&&covered| covered).count() as u64;
        let lines_covered = counts.lines.values().filter(|&&hits| hits > 0).count() as u64;
        totals.add(*counts);
        lines.push(format!(
            "| {} | {} | {} | {} |",
            file,
            format_ratio(functions_covered, counts.functions.len() as u64),
            format_ratio(lines_covered, counts.lines.len() as u64),
            format_ratio(0, 0)
        ));
    }

    /*lines.push(format!(
        "| **Totals** | {} | {} | {} |",
        format_ratio(totals.functions_covered, totals.functions_total),
        format_ratio(totals.lines_covered, totals.lines_total),
        format_ratio(totals.regions_covered, totals.regions_total)
    ));*/

    lines.join("\n")
}

fn format_ratio(covered: u64, total: u64) -> String {
    if total == 0 {
        return "0.00% (0/0)".to_string();
    }
    let pct = (covered as f64) * 100.0 / (total as f64);
    format!("{:.2}% ({}/{})", pct, covered, total)
}
