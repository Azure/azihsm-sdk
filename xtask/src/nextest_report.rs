// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fs;

use glob::glob;
use junit_parser::TestSuites;

use crate::Xtask;
use crate::XtaskCtx;

/// Run nextest report
#[derive(clap::Parser)]
pub struct NextestReport {
    // Add command-line arguments here as needed
}

/// Derive the likely cargo nextest command from a profile name
fn profile_to_command(profile_name: &str) -> String {
    // Map known profile names to their corresponding commands
    match profile_name {
        "ci-mock" => "cargo nextest run --no-fail-fast --features mock".to_string(),
        "ci-mock-table-4" => {
            "cargo nextest run --no-fail-fast --features mock,table-4 --package azihsm_ddi"
                .to_string()
        }
        "ci-mock-table-64" => {
            "cargo nextest run --no-fail-fast --features mock,table-64 --package azihsm_ddi"
                .to_string()
        }
        // For unknown profiles, construct a generic command showing the profile
        _ => format!("cargo nextest run --profile {}", profile_name),
    }
}

impl Xtask for NextestReport {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running nextest-report");

        let mut test_suites_total = TestSuites::default();

        let mut profile_data = Vec::new();

        // Discover all junit.xml files under target/nextest/*/junit.xml
        for entry in glob("./target/nextest/*/junit.xml")? {
            let junit_path = entry?;

            // Read the JUnit XML file
            match fs::read_to_string(&junit_path) {
                Ok(xml_content) => {
                    // Parse the JUnit XML
                    let test_suites = junit_parser::from_reader(xml_content.as_bytes())?;

                    // Extract profile name from the path
                    // Path format: ./target/nextest/{profile}/junit.xml
                    let profile_name = junit_path
                        .parent()
                        .and_then(|p| p.file_name())
                        .and_then(|n| n.to_str())
                        .map(String::from)
                        .unwrap_or_else(|| {
                            let path_str = junit_path.to_string_lossy();
                            log::warn!("Could not extract profile name from path: {}", path_str);
                            format!("unknown-{}", path_str)
                        });

                    // Derive the command for this profile
                    let command = profile_to_command(&profile_name);

                    // Add data from JUnit XML to total data structure
                    test_suites_total.suites.extend(test_suites.suites);

                    profile_data.push((
                        command,
                        test_suites.tests,
                        test_suites.failures,
                        test_suites.skipped,
                    ));
                }
                Err(err) => {
                    let path_str = junit_path.to_string_lossy();
                    log::warn!(
                        "Failed to read JUnit XML file at '{}': {}",
                        path_str,
                        err
                    );
                }
            }
        }

        // Calculate total tests, failures, and skipped
        let (total_tests, total_failures, total_skipped) = profile_data.iter().fold(
            (0, 0, 0),
            |(tests, failures, skipped), (_command, t, f, s)| {
                (tests + t, failures + f, skipped + s)
            },
        );
        test_suites_total.tests = total_tests;
        test_suites_total.failures = total_failures;
        test_suites_total.skipped = total_skipped;

        // Generate markdown report
        let mut markdown = String::new();
        markdown.push_str("# Test Results\n\n");

        // Helper closure to format command entries in the report
        let format_command_entry =
            |cmd: &str, value: u64| format!("  - {}\n    - {}\n", cmd, value);

        markdown.push_str(&format!("- **Total Tests**: {}\n", test_suites_total.tests));
        for (command, tests, _, _) in &profile_data {
            markdown.push_str(&format_command_entry(command, *tests));
        }

        markdown.push_str(&format!(
            "- **Total Failures**: {}\n",
            test_suites_total.failures
        ));
        for (command, _, failures, _) in &profile_data {
            markdown.push_str(&format_command_entry(command, *failures));
        }

        markdown.push_str(&format!(
            "- **Total Skipped**: {}\n",
            test_suites_total.skipped
        ));
        for (command, _, _, skipped) in &profile_data {
            markdown.push_str(&format_command_entry(command, *skipped));
        }

        markdown.push('\n');

        // Collect all failed test cases
        let mut failed_tests = Vec::new();
        for suite in &test_suites_total.suites {
            for case in &suite.cases {
                if case.status.is_failure() {
                    failed_tests.push((
                        suite.name.clone(),
                        case.name.clone(),
                        case.status.failure_as_ref().message.clone(),
                    ));
                }
            }
        }

        // Add failed test cases to the report
        if !failed_tests.is_empty() {
            markdown.push_str("## Failed Tests\n\n");
            for (suite_name, test_name, failure_message) in failed_tests {
                markdown.push_str(&format!("### {} - {}\n\n", suite_name, test_name));
                markdown.push_str("```\n");
                markdown.push_str(&failure_message);
                markdown.push_str("\n```\n\n");
            }
        }

        // Write to GITHUB_STEP_SUMMARY environment variable
        if let Ok(summary_path) = std::env::var("GITHUB_STEP_SUMMARY") {
            fs::write(&summary_path, &markdown)?;
            log::trace!("Report written to GITHUB_STEP_SUMMARY");
        } else {
            // If not in GitHub Actions, just print to stdout
            println!("{}", markdown);
        }

        // Write total & skipped to GITHUB_OUTPUT environment variable
        if let Ok(output_path) = std::env::var("GITHUB_OUTPUT") {
            let mut output = String::new();
            output.push_str(&format!("TOTAL_TESTS={}\n", test_suites_total.tests));
            output.push_str(&format!("SKIPPED_TESTS={}\n", test_suites_total.skipped));
            fs::write(&output_path, &output)?;
            log::trace!("Output written to GITHUB_OUTPUT");
        }

        log::trace!("done nextest-report");
        Ok(())
    }
}
