// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to generate a markdown coverage report from Cobertura XML.

use std::collections::BTreeMap;
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

#[derive(Default, Debug, Clone, Copy)]
struct CoverageCounts {
    functions_total: u64,
    functions_covered: u64,
    lines_total: u64,
    lines_covered: u64,
    regions_total: u64,
    regions_covered: u64,
}

impl CoverageCounts {
    fn add(&mut self, other: CoverageCounts) {
        self.functions_total += other.functions_total;
        self.functions_covered += other.functions_covered;
        self.lines_total += other.lines_total;
        self.lines_covered += other.lines_covered;
        self.regions_total += other.regions_total;
        self.regions_covered += other.regions_covered;
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
        println!("{}", table);

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

    let mut per_file: BTreeMap<String, CoverageCounts> = BTreeMap::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => match e.name().as_ref() {
                b"class" => {
                    if let Some(filename) = get_attr_value(e, b"filename")? {
                        current_file = Some(filename.to_string());
                        per_file.entry(filename.to_string()).or_default();
                    }
                }
                b"method" => {
                    if current_file.is_some() {
                        in_method = true;
                        method_has_hit = false;
                        if let Some(entry) = current_file.as_ref().and_then(|f| per_file.get_mut(f))
                        {
                            entry.functions_total += 1;
                        }
                    }
                }
                b"line" => {
                    if let Some(file) = current_file.as_ref() {
                        if let Some(entry) = per_file.get_mut(file) {
                            let hits = get_attr_value(e, b"hits")?
                                .and_then(|v| v.parse::<u64>().ok())
                                .unwrap_or(0);

                            entry.lines_total += 1;
                            if hits > 0 {
                                entry.lines_covered += 1;
                            }

                            if in_method && hits > 0 {
                                method_has_hit = true;
                            }

                            let has_branch = get_attr_value(e, b"branch")?
                                .map(|v| v == "true")
                                .unwrap_or(false);

                            if let Some((covered, total)) =
                                get_attr_value(e, b"condition-coverage")?
                                    .and_then(|v| parse_condition_coverage(&v))
                            {
                                entry.regions_total += total;
                                entry.regions_covered += covered;
                            } else if has_branch {
                                entry.regions_total += 1;
                                if hits > 0 {
                                    entry.regions_covered += 1;
                                }
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
                                    entry.functions_covered += 1;
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
        totals.add(*counts);
        lines.push(format!(
            "| {} | {} | {} | {} |",
            file,
            format_ratio(counts.functions_covered, counts.functions_total),
            format_ratio(counts.lines_covered, counts.lines_total),
            format_ratio(counts.regions_covered, counts.regions_total)
        ));
    }

    lines.push(format!(
        "| **Totals** | {} | {} | {} |",
        format_ratio(totals.functions_covered, totals.functions_total),
        format_ratio(totals.lines_covered, totals.lines_total),
        format_ratio(totals.regions_covered, totals.regions_total)
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
