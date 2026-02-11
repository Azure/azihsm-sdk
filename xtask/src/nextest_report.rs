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

impl Xtask for NextestReport {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running nextest-report");

        let mut test_suites_total = TestSuites::default();

        let mut profile_data = Vec::new();

        // Discover all junit.xml files under target/nextest/**/junit.xml
        for entry in glob("./target/nextest/**/junit.xml")? {
            let junit_path = entry?;

            // Read the JUnit XML file
            if let Ok(xml_content) = fs::read_to_string(&junit_path) {
                // Parse the JUnit XML
                let test_suites = junit_parser::from_reader(xml_content.as_bytes())?;

                // Extract profile name from the path
                // Path format: ./target/nextest/{profile}/junit.xml
                let profile_name = junit_path
                    .parent()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");

                // Add data from JUnit XML to total data structure
                test_suites_total.suites.extend(test_suites.suites);

                profile_data.push((
                    profile_name.to_string(),
                    test_suites.tests,
                    test_suites.failures,
                    test_suites.skipped,
                ));
            }
        }

        // Calculate total tests, failures, and skipped
        test_suites_total.tests = profile_data.iter().map(|(_, t, _, _)| t).sum();
        test_suites_total.failures = profile_data.iter().map(|(_, _, f, _)| f).sum();
        test_suites_total.skipped = profile_data.iter().map(|(_, _, _, s)| s).sum();

        // Generate markdown report
        let mut markdown = String::new();
        markdown.push_str("# Test Results\n\n");
        markdown.push_str(&format!("- **Total Tests**: {}\n", test_suites_total.tests));
        for (profile, tests, _, _) in &profile_data {
            markdown.push_str(&format!("  - {}: {}\n", profile, tests));
        }

        markdown.push_str(&format!(
            "- **Total Failures**: {}\n",
            test_suites_total.failures
        ));
        for (profile, _, failures, _) in &profile_data {
            markdown.push_str(&format!("  - {}: {}\n", profile, failures));
        }

        markdown.push_str(&format!(
            "- **Total Skipped**: {}\n",
            test_suites_total.skipped
        ));
        for (profile, _, _, skipped) in &profile_data {
            markdown.push_str(&format!("  - {}: {}\n", profile, skipped));
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
