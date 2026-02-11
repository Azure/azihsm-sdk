// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run various repo-specific checks

use clap::Parser;
use xshell::Shell;

use crate::audit;
use crate::clippy;
use crate::copyright;
use crate::coverage;
use crate::fmt;
use crate::nextest;
use crate::nextest_history;
use crate::nextest_report;
use crate::setup;
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
    /// Run nextest tests
    #[clap(long)]
    nextest: bool,
    /// Run nextest-history
    #[clap(long)]
    nextest_history: bool,
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
    /// Skip TOML formatting
    #[clap(long)]
    pub skip_toml: bool,
    /// Skip Clang formatting
    #[clap(long)]
    pub skip_clang: bool,
    /// Skip specifying toolchain for formatting checks
    #[clap(long)]
    skip_toolchain: bool,
    /// Package to run tests for
    #[clap(long)]
    package: Option<String>,
    /// Features to enable when running tests
    #[clap(long)]
    features: Option<String>,
    /// The nextest profile to use
    #[clap(long)]
    profile: Option<String>,
}

impl Xtask for Precheck {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running precheck");

        let sh = Shell::new()?;

        // if no specific stages are requested, run all stages except code coverage
        let stage = self.stage.unwrap_or(Stage {
            setup: true,
            copyright: true,
            audit: true,
            fmt: true,
            clippy: true,
            coverage: false,
            nextest: true,
            nextest_history: false,
            nextest_report: false,
            all: false,
        });

        if stage.setup || stage.all {
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

            let setup = setup::Setup {
                force: false,
                config: Some(config_path),
            };
            setup.run(ctx.clone())?;
        }

        // Run Copyright
        if stage.copyright || stage.all {
            let copyright = copyright::Copyright { fix: false };
            copyright.run(ctx.clone())?;
        }

        // Run Audit
        if stage.audit || stage.all {
            let audit = audit::Audit {};
            audit.run(ctx.clone())?;
        }

        // Cargo format
        if stage.fmt || stage.all {
            let fmt = fmt::Fmt {
                fix: false,                  // Do not fix formatting issues by default
                skip_toml: self.skip_toml,   // Pass through skip_toml flag
                skip_clang: self.skip_clang, // Pass through skip_clang flag
                toolchain: if self.skip_toolchain {
                    None
                } else {
                    Some("nightly".to_string()) // Use nightly toolchain by default
                },
            };
            fmt.run(ctx.clone())?;
        }

        // Cargo Clippy
        if stage.clippy || stage.all {
            let clippy = clippy::Clippy {};
            clippy.run(ctx.clone())?;
        }

        if stage.nextest || stage.all {
            if self.package.is_none() && self.features.is_none() {
                // SDK Run all mock tests
                let nextest = nextest::Nextest {
                    features: Some("mock".to_string()),
                    package: None,
                    no_default_features: false,
                    filterset: None,
                    profile: Some("ci-mock".to_string()),
                };
                nextest.run(ctx.clone())?;

                #[cfg(not(target_os = "windows"))]
                {
                    // SDK Run azihsm_ddi mock tests table-4
                    let nextest = nextest::Nextest {
                        features: Some("mock,table-4".to_string()),
                        package: Some("azihsm_ddi".to_string()),
                        no_default_features: false,
                        filterset: None,
                        profile: Some("ci-mock-table-4".to_string()),
                    };
                    nextest.run(ctx.clone())?;

                    // SDK Run azihsm_ddi mock tests table-64
                    let nextest = nextest::Nextest {
                        features: Some("mock,table-64".to_string()),
                        package: Some("azihsm_ddi".to_string()),
                        no_default_features: false,
                        filterset: None,
                        profile: Some("ci-mock-table-64".to_string()),
                    };
                    nextest.run(ctx.clone())?;
                }
            } else {
                let nextest = nextest::Nextest {
                    features: self.features,
                    package: self.package,
                    no_default_features: false,
                    filterset: None,
                    profile: self.profile,
                };
                nextest.run(ctx.clone())?;
            }
        }

        // Run code coverage
        if stage.coverage || stage.all {
            let coverage = coverage::Coverage {};
            coverage.run(ctx.clone())?;
        }

        // Run nextest report
        if stage.nextest_report || stage.all {
            let nextest_report = nextest_report::NextestReport {};
            nextest_report.run(ctx.clone())?;
        }

        // Run nextest history
        if stage.nextest_history || stage.all {
            let nextest_history = nextest_history::NextestHistory {};
            nextest_history.run(ctx)?;
        }

        log::trace!("done precheck");
        Ok(())
    }
}
