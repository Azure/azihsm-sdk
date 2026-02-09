// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fs;
use std::path::PathBuf;

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

        let nextest_profiles = ["ci-mock", "ci-mock-table-4", "ci-mock-table-64"];
        let nextest_cmds = [
            "cargo nextest run --no-fail-fast --features mock",
            "cargo nextest run --no-fail-fast --features mock,table-4 --package azihsm_ddi",
            "cargo nextest run --no-fail-fast --features mock,table-64 --package azihsm_ddi",
        ];

        let mut test_suites_total = TestSuites::default();

        let mut vec_tests = Vec::new();
        let mut vec_failures = Vec::new();
        let mut vec_skipped = Vec::new();

        for profile in &nextest_profiles {
            let junit_path = PathBuf::from(format!("./target/nextest/{}/junit.xml", profile));

            // Read the JUnit XML file (ignore if it doesn't exist)
            if let Ok(xml_content) = fs::read_to_string(&junit_path) {
                // Parse the JUnit XML
                let test_suites = junit_parser::from_reader(xml_content.as_bytes())?;

                // Add data from JUnit XML to total data structure
                test_suites_total.suites.extend(test_suites.suites);

                vec_tests.push(test_suites.tests);
                vec_failures.push(test_suites.failures);
                vec_skipped.push(test_suites.skipped);
            }
        }

        // Generate markdown report
        let mut markdown = String::new();
        markdown.push_str("# Test Results\n\n");
        markdown.push_str(&format!(
            "-**Total Tests**: {}\n",
            vec_tests.iter().sum::<u64>()
        ));
        for (i, val) in vec_tests.iter().enumerate() {
            markdown.push_str(&format!("  -{}\n    -{}\n", nextest_cmds[i], val));
        }

        markdown.push_str(&format!(
            "-**Total Failures**: {}\n",
            vec_failures.iter().sum::<u64>()
        ));
        for (i, val) in vec_failures.iter().enumerate() {
            markdown.push_str(&format!("  -{}\n    -{}\n", nextest_cmds[i], val));
        }

        markdown.push_str(&format!(
            "-**Total Skipped**: {}\n",
            vec_skipped.iter().sum::<u64>()
        ));
        for (i, val) in vec_skipped.iter().enumerate() {
            markdown.push_str(&format!("  -{}\n    -{}\n", nextest_cmds[i], val));
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
