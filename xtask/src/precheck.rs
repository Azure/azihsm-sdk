// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run various repo-specific checks

use clap::Parser;
use xshell::Shell;

use crate::audit::Audit;
use crate::clippy::Clippy;
use crate::copyright::Copyright;
use crate::coverage::Coverage;
use crate::coverage_report::CoverageReport;
use crate::fmt::Fmt;
#[cfg(target_os = "linux")]
use crate::integration_tests;
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
    /// Run nextest with cli options (features, package, profile, exclude)
    #[clap(long, conflicts_with_all = ["nextest_min", "nextest_full"])]
    nextest: bool,
    /// Run minimal nextest tests (skips resiliency, openssl, and native/cpp tests)
    #[clap(long, conflicts_with_all = ["nextest", "nextest_full"])]
    nextest_min: bool,
    /// Run the full nextest tests
    #[clap(long, conflicts_with_all = ["nextest", "nextest_min"])]
    nextest_full: bool,
    /// Run nextest-report
    #[clap(long)]
    nextest_report: bool,
}

impl Stage {
    /// Merge another `Stage` into this one
    fn merge(&mut self, other: &Stage) {
        self.setup = self.setup || other.setup;
        self.copyright = self.copyright || other.copyright;
        self.validate_members = self.validate_members || other.validate_members;
        self.audit = self.audit || other.audit;
        self.fmt = self.fmt || other.fmt;
        self.clippy = self.clippy || other.clippy;
        self.coverage = self.coverage || other.coverage;
        self.coverage_report = self.coverage_report || other.coverage_report;
        self.nextest = self.nextest || other.nextest;
        self.nextest_min = self.nextest_min || other.nextest_min;
        self.nextest_full = self.nextest_full || other.nextest_full;
        self.nextest_report = self.nextest_report || other.nextest_report;
    }

    /// Return a Stage instance with minimal checks enabled (fmt and nextest_min)
    fn min() -> Stage {
        Stage {
            setup: false,
            copyright: false,
            validate_members: false,
            audit: false,
            fmt: true,
            clippy: false,
            coverage: false,
            coverage_report: false,
            nextest: false,
            nextest_min: true,
            nextest_full: false,
            nextest_report: false,
        }
    }

    /// Return a Stage instance with full checks enabled (everything except coverage, coverage_report & nextest_report)
    fn full() -> Stage {
        Stage {
            setup: true,
            copyright: true,
            validate_members: true,
            audit: true,
            fmt: true,
            clippy: true,
            coverage: false,        // coverage is optional
            coverage_report: false, // coverage report is optional (intended only for CI)
            nextest: false,
            nextest_min: false,
            nextest_full: true,
            nextest_report: false, // nextest report is optional (intended only for CI)
        }
    }

    /// Return a Stage instance with all checks enabled
    fn all() -> Stage {
        Stage {
            setup: true,
            copyright: true,
            validate_members: true,
            audit: true,
            fmt: true,
            clippy: true,
            coverage: true,
            coverage_report: true,
            nextest: false,     // subset of nextest_full
            nextest_min: false, // subset of nextest_full
            nextest_full: true,
            nextest_report: true,
        }
    }
}

/// Xtask to run various repo-specific checks
#[derive(Parser)]
#[clap(about = "Run various checks")]
pub struct Precheck {
    /// Specify which checks to run
    #[clap(flatten)]
    stage: Option<Stage>,
    /// Run the full set of checks:
    /// setup, copyright, validate_members, audit, fmt, clippy, nextest_full
    #[clap(long, conflicts_with = "all")]
    pub full: bool,
    /// Run all checks
    #[clap(long, conflicts_with = "full")]
    pub all: bool,
    /// Skip taplo (TOML formatting) (used with --fmt)
    #[clap(long)]
    pub skip_taplo: bool,
    /// Skip audit (used with --audit/--full)
    #[clap(long)]
    pub skip_audit: bool,
    /// Skip Clang formatting (used with --fmt)
    #[clap(long)]
    pub skip_clang: bool,
    /// Skip specifying toolchain for formatting checks (used with --fmt)
    #[clap(long)]
    skip_toolchain: bool,
    /// Crates to exclude (used with --clippy/--nextest/--nextest-min/--nextest-full)
    #[clap(long = "exclude")]
    exclude: Vec<String>,
    /// Package to run tests for (used with --nextest)
    #[clap(long, requires = "nextest")]
    package: Option<String>,
    /// Features to enable when running tests (used with --nextest)
    #[clap(long, requires = "nextest")]
    features: Option<String>,
    /// The nextest profile to use (used with --nextest/--nextest-min/--nextest-full)
    #[clap(long)]
    profile: Option<String>,
}

impl Xtask for Precheck {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running precheck");

        let sh = Shell::new()?;

        // choose defaults based on --all/--full flags & whether CLI-provided stages exist
        let mut stage = if self.all {
            Stage::all()
        } else if self.full {
            Stage::full()
        } else if self.stage.is_some() {
            Stage::default()
        } else {
            Stage::min()
        };

        if let Some(stage_cli) = self.stage {
            // merge defaults with CLI-provided stages
            stage.merge(&stage_cli);
        }

        if stage.setup {
            // first try path of .cargo inside current directory
            let mut config_path = ".cargo".to_string();
            if !sh.path_exists(&config_path) {
                // next try path of .cargo inside parent directory
                config_path = "../.cargo".to_string();
                if !sh.path_exists(&config_path) {
                    anyhow::bail!("Could not find .cargo directory at {}", config_path);
                }
            }

            config_path.push_str("/config.toml");

            Setup {
                force: false,
                config: Some(config_path),
                skip_taplo: self.skip_taplo,
                skip_audit: self.skip_audit,
            }
            .run(ctx.clone())?;
        }

        // Run Copyright
        if stage.copyright {
            Copyright { fix: false }.run(ctx.clone())?;
        }

        // Run ValidateMembers
        if stage.validate_members {
            ValidateMembers { fix: false }.run(ctx.clone())?;
        }

        // Run Audit
        if stage.audit && !self.skip_audit {
            Audit {}.run(ctx.clone())?;
        }

        // Cargo format
        if stage.fmt {
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
        if stage.clippy {
            Clippy {
                exclude: self.exclude.clone(),
            }
            .run(ctx.clone())?;
        }

        if stage.nextest {
            Nextest {
                features: self.features.clone(),
                package: self.package.clone(),
                no_default_features: false,
                filterset: None,
                profile: self.profile.clone(),
                exclude: self.exclude.clone(),
            }
            .run(ctx.clone())?;
        }

        // Minimal nextest: run mock tests, skipping resiliency, openssl, and cpp tests
        if stage.nextest_min {
            let mut excludes = self.exclude.clone();
            for pkg in [
                "azihsm_api_tests",
                "azihsm_ossl_provider",
                "azihsm_res_test_dev",
                "azihsm_resiliency_test_helpers",
                "provider-integration-tests-cli",
                "provider-integration-tests-capi",
                "provider-integration-tests-nginx",
                "resiliency_stress",
                "resiliency_macro",
            ] {
                if !excludes.iter().any(|e| e == pkg) {
                    excludes.push(pkg.to_string());
                }
            }

            Nextest {
                features: Some("mock".to_string()),
                package: None,
                no_default_features: false,
                filterset: None,
                profile: self.profile.clone().or_else(|| Some("ci-mock".to_string())),
                exclude: excludes,
            }
            .run(ctx.clone())?;
        }

        // Full nextest: run the complete set of tests including resiliency, openssl, and native/cpp
        if stage.nextest_full {
            // SDK Run all mock tests
            Nextest {
                features: Some("mock".to_string()),
                package: None,
                no_default_features: false,
                filterset: None,
                profile: self.profile.clone().or(Some("ci-mock".to_string())),
                exclude: self.exclude.clone(),
            }
            .run(ctx.clone())?;

            // SDK Run resiliency fault-injection tests (requires res-test
            // feature for the fault-injection DDI device)
            if !self.exclude.iter().any(|e| e == "azihsm_api_tests") {
                Nextest {
                    features: Some("mock,res-test".to_string()),
                    package: Some("azihsm_api_tests".to_string()),
                    no_default_features: false,
                    filterset: Some("test(resiliency::fault_injection::)".to_string()),
                    profile: self.profile.clone().or(Some("ci-mock-res".to_string())),
                    exclude: self.exclude.clone(),
                }
                .run(ctx.clone())?;
            }

            #[cfg(not(target_os = "windows"))]
            {
                // SDK Run azihsm_ddi mock tests table-4
                Nextest {
                    features: Some("mock,table-4".to_string()),
                    package: Some("azihsm_ddi".to_string()),
                    no_default_features: false,
                    filterset: None,
                    profile: self.profile.clone().or(Some("ci-mock-table-4".to_string())),
                    exclude: self.exclude.clone(),
                }
                .run(ctx.clone())?;

                // SDK Run azihsm_ddi mock tests table-64
                Nextest {
                    features: Some("mock,table-64".to_string()),
                    package: Some("azihsm_ddi".to_string()),
                    no_default_features: false,
                    filterset: None,
                    profile: self
                        .profile
                        .clone()
                        .or(Some("ci-mock-table-64".to_string())),
                    exclude: self.exclude.clone(),
                }
                .run(ctx.clone())?;

                // OSSL Provider integration tests (CLI + C API, Linux only)
                #[cfg(target_os = "linux")]
                integration_tests::IntegrationTest {}.run(ctx.clone())?;
            }
        }

        // Run code coverage
        if stage.coverage {
            Coverage {}.run(ctx.clone())?;
        }

        // Run nextest report
        if stage.nextest_report {
            NextestReport {}.run(ctx.clone())?;
        }

        // Run code coverage report
        if stage.coverage_report {
            CoverageReport {}.run(ctx)?;
        }

        log::trace!("done precheck");
        Ok(())
    }
}
