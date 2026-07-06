// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run various repo-specific checks

use clap::Parser;

use crate::audit::Audit;
use crate::clippy::Clippy;
use crate::copyright::Copyright;
use crate::coverage::Coverage;
use crate::coverage_report::CoverageReport;
use crate::fmt::Fmt;
use crate::nextest::Nextest;
use crate::nextest_report::NextestReport;
use crate::setup::Setup;
use crate::validate_members::ValidateMembers;
use crate::Xtask;
use crate::XtaskCtx;

#[derive(Parser, Debug, Clone, Default)]
struct Stage {
    /// Run setup checks
    #[clap(long)]
    setup: bool,
    /// Run copyright checks
    #[clap(long)]
    copyright: bool,
    /// Run validate members checks
    #[clap(long)]
    validate_members: bool,
    /// Run audit checks
    #[clap(long)]
    audit: bool,
    /// Run formatting checks
    #[clap(long)]
    fmt: bool,
    /// Run clippy checks
    #[clap(long)]
    clippy: bool,
    /// Run code coverage
    #[clap(long)]
    coverage: bool,
    /// Run code coverage-report
    #[clap(long)]
    coverage_report: bool,
    /// Run nextest tests
    #[clap(long)]
    nextest: bool,
    /// Run nextest-report
    #[clap(long)]
    nextest_report: bool,
    /// Run all checks (default if no specific checks are selected)
    #[clap(long)]
    all: bool,
}

/// Xtask to run various repo-specific checks
#[derive(Parser)]
#[clap(about = "Run various checks")]
pub struct Precheck {
    /// Specify which checks to run
    #[clap(flatten)]
    stage: Option<Stage>,
    /// Skip taplo (TOML formatting)
    #[clap(long)]
    pub skip_taplo: bool,
    /// Skip audit
    #[clap(long)]
    pub skip_audit: bool,
    /// Skip Clang formatting
    #[clap(long)]
    pub skip_clang: bool,
    /// Skip cleaning existing llvm-cov artifacts before running coverage
    #[clap(long)]
    pub skip_clean: bool,
    /// Skip specifying toolchain for formatting checks
    #[clap(long)]
    skip_toolchain: bool,
    /// Crates to exclude from clippy
    #[clap(long = "exclude")]
    exclude: Vec<String>,
    /// Package to run tests for
    #[clap(long, short = 'p')]
    package: Option<String>,
    /// Features to enable when running tests
    #[clap(long, short = 'F')]
    features: Option<String>,
    /// Test filterset (see https://nexte.st/docs/filtersets)
    #[clap(long, short = 'E')]
    filterset: Option<String>,
    /// The nextest profile to use
    #[clap(long)]
    profile: Option<String>,
    /// Pass through to `cargo install --config`; accepts either `KEY=VALUE`
    /// or a path to a Cargo `config.toml` file.
    /// Only used for --setup ignored otherwise.
    #[clap(long)]
    pub config: Option<String>,
    /// Do not append the default build location of the azihsm_api_native object file to LLVM_COV_FLAGS (used with --coverage-report)
    #[clap(long)]
    pub no_default_native: bool,
    /// Additional paths to object files to append to LLVM_COV_FLAGS (used with --coverage-report)
    #[clap(long)]
    pub additional_obj_paths: Vec<String>,
    /// The nextest test target to run
    #[clap(long)]
    pub test: Option<String>,
    /// Test name filters
    #[clap(long)]
    filter: Vec<String>,
}

impl Xtask for Precheck {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running precheck");

        // if no specific stages are requested, run all stages except code coverage, nextest report and coverage report
        let stage = self.stage.unwrap_or(Stage {
            setup: true,
            copyright: true,
            validate_members: true,
            audit: true,
            fmt: true,
            clippy: true,
            coverage: false,        // coverage is optional
            coverage_report: false, // coverage report is optional (intended only for CI)
            nextest: true,
            nextest_report: false, // nextest report is optional (intended only for CI)
            all: false,
        });

        if stage.setup || stage.all {
            Setup {
                force: false,
                config: self.config,
                skip_taplo: self.skip_taplo,
                skip_audit: self.skip_audit,
            }
            .run(ctx.clone())?;
        }

        // Run Copyright
        if stage.copyright || stage.all {
            Copyright { fix: false }.run(ctx.clone())?;
        }

        // Run ValidateMembers
        if stage.validate_members || stage.all {
            ValidateMembers {
                fix: false,
                skip_taplo: self.skip_taplo,
            }
            .run(ctx.clone())?;
        }

        // Run Audit
        if (stage.audit || stage.all) && !self.skip_audit {
            Audit {}.run(ctx.clone())?;
        }

        // Cargo format
        if stage.fmt || stage.all {
            Fmt {
                fix: false,                  // Do not fix formatting issues by default
                skip_taplo: self.skip_taplo, // Pass through skip_taplo flag
                skip_clang: self.skip_clang, // Pass through skip_clang flag
                toolchain: if self.skip_toolchain {
                    None
                } else {
                    Some("nightly".to_string()) // Use nightly toolchain by default
                },
            }
            .run(ctx.clone())?;
        }

        // Cargo Clippy
        if stage.clippy || stage.all {
            Clippy {
                exclude: self.exclude.clone(),
            }
            .run(ctx.clone())?;
        }

        if stage.nextest || stage.all {
            if self.package.is_none()
                && self.features.is_none()
                && self.filterset.is_none()
                && self.test.is_none()
                && self.filter.is_empty()
            {
                // Run default tests
                let tests = default_tests(&self.exclude, self.profile.clone());
                run_tests(tests, false, self.skip_clean, ctx.clone())?;

                #[cfg(not(target_os = "windows"))]
                {
                    // Run azihsm_ddi mock tests
                    let ddi_test_runs = ddi_tests(&self.exclude, self.profile.clone());
                    run_tests(ddi_test_runs, false, self.skip_clean, ctx.clone())?;
                }
            } else {
                Nextest {
                    features: self.features.clone(),
                    package: self.package.clone(),
                    no_default_features: false,
                    filterset: self.filterset.clone(),
                    profile: self.profile.clone(),
                    exclude: self.exclude.clone(),
                    test: self.test.clone(),
                    filter: self.filter.clone(),
                }
                .run(ctx.clone())?;
            }
        }

        // Run code coverage
        if stage.coverage || stage.all {
            if self.package.is_none()
                && self.features.is_none()
                && self.filterset.is_none()
                && self.test.is_none()
                && self.filter.is_empty()
            {
                // Run default tests with coverage
                let tests = default_tests(&self.exclude, self.profile.clone());
                run_tests(tests, true, self.skip_clean, ctx.clone())?;
            } else {
                Coverage {
                    features: self.features.clone(),
                    package: self.package.clone(),
                    no_default_features: false,
                    filterset: self.filterset.clone(),
                    profile: self.profile.clone(),
                    exclude: self.exclude.clone(),
                    test: self.test.clone(),
                    filter: self.filter.clone(),
                    skip_clean: self.skip_clean,
                }
                .run(ctx.clone())?;
            }
        }

        // Run nextest report
        if stage.nextest_report || stage.all {
            NextestReport {}.run(ctx.clone())?;
        }

        // Run code coverage report
        if stage.coverage_report || stage.all {
            CoverageReport {
                no_default_native: self.no_default_native,
                additional_obj_paths: self.additional_obj_paths.clone(),
            }
            .run(ctx.clone())?;
        }

        log::trace!("done precheck");
        Ok(())
    }
}

// Helper function to define default test parameters for --nextest and --coverage
fn default_tests(exclude: &[String], profile: Option<String>) -> Vec<Nextest> {
    let mut tests = Vec::new();

    let mut mock_exclude = exclude.to_owned();

    mock_exclude.extend(vec![
        "provider-integration-tests-cli".to_string(),
        "provider-integration-tests-capi".to_string(),
    ]);

    // SDK Run all mock tests
    tests.push(Nextest {
        features: Some("mock".to_string()),
        package: None,
        no_default_features: false,
        filterset: None,
        profile: profile.clone().or(Some("ci-mock".to_string())),
        exclude: mock_exclude,
        test: None,
        filter: vec![],
    });

    // SDK Run resiliency fault-injection tests (requires res-test
    // feature for the fault-injection DDI device)
    if !exclude.iter().any(|e| e == "azihsm_api_tests") {
        tests.push(Nextest {
            features: Some("mock,res-test".to_string()),
            package: Some("azihsm_api_tests".to_string()),
            no_default_features: false,
            filterset: Some("test(resiliency::fault_injection::)".to_string()),
            profile: profile.clone().or(Some("ci-mock-res".to_string())),
            exclude: exclude.to_owned(),
            test: None,
            filter: vec![],
        });
    }

    // Run emu smoke tests
    if !exclude.iter().any(|e| e == "azihsm_ddi_mbor_types") {
        tests.push(Nextest {
            features: Some("emu".to_string()),
            package: Some("azihsm_ddi_mbor_types".to_string()),
            no_default_features: false,
            filterset: None,
            profile: profile.clone().or(Some("ci-emu-smoke".to_string())),
            exclude: exclude.to_owned(),
            test: Some("azihsm_ddi_tests".to_string()),
            filter: vec!["smoke".to_string()],
        });
    }

    tests
}

// Helper function to define test parameters for Linux-specific azihsm_ddi mock tests
#[cfg(not(target_os = "windows"))]
fn ddi_tests(exclude: &[String], profile: Option<String>) -> Vec<Nextest> {
    let mut tests = Vec::new();

    if !exclude.iter().any(|e| e == "azihsm_ddi_mbor_types") {
        // SDK Run azihsm_ddi_mbor_types mock tests table-4
        tests.push(Nextest {
            features: Some("mock,table-4".to_string()),
            package: Some("azihsm_ddi_mbor_types".to_string()),
            no_default_features: false,
            filterset: None,
            profile: profile.clone().or(Some("ci-mock-table-4".to_string())),
            exclude: exclude.to_owned(),
            test: None,
            filter: vec![],
        });

        // SDK Run azihsm_ddi_mbor_types mock tests table-64
        tests.push(Nextest {
            features: Some("mock,table-64".to_string()),
            package: Some("azihsm_ddi_mbor_types".to_string()),
            no_default_features: false,
            filterset: None,
            profile: profile.clone().or(Some("ci-mock-table-64".to_string())),
            exclude: exclude.to_owned(),
            test: None,
            filter: vec![],
        });
    }

    if !exclude.iter().any(|e| e == "azihsm_ddi_tbor_types") {
        // SDK Run azihsm_ddi_tbor_types tests through the emu
        // backend (in-process firmware).
        tests.push(Nextest {
            features: Some("emu".to_string()),
            package: Some("azihsm_ddi_tbor_types".to_string()),
            no_default_features: false,
            filterset: None,
            profile: profile.clone().or(Some("ci-tbor-emu".to_string())),
            exclude: exclude.to_owned(),
            test: None,
            filter: vec![],
        });
    }

    tests
}

// Helper function to run tests defined by other helper functions
fn run_tests(
    tests: Vec<Nextest>,
    coverage: bool,
    skip_clean: bool,
    ctx: XtaskCtx,
) -> anyhow::Result<()> {
    let mut first_run = true;
    for test in tests {
        if coverage {
            let mut cov = Coverage::from(test);
            if !first_run {
                cov.skip_clean = true;
            } else {
                cov.skip_clean = skip_clean;
            }
            first_run = false;
            cov.run(ctx.clone())?;
        } else {
            test.run(ctx.clone())?;
        }
    }
    Ok(())
}
