// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run various repo-specific checks

use clap::Parser;
use clap::Subcommand;

use crate::clippy;
use crate::copyright;
use crate::fmt;
use crate::native;
use crate::nextest;
use crate::setup;
use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run various repo-specific checks
#[derive(Parser)]
#[clap(about = "Run various checks")]
pub struct Precheck {
    #[clap(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Clone)]
enum Commands {
    Setup {
        #[clap(long)]
        config: Option<String>,

        #[clap(long)]
        symcrypt_install_method: Option<String>,

        #[clap(long)]
        symcrypt_version: Option<String>,
    },
    Copyright,
    Fmt {
        #[clap(long)]
        skip_toolchain: bool,
    },
    Clippy,
    #[clap(alias = "nbt")]
    NativeBuildAndTest,
    MockTests,
    AzihsmDdiTests {
        #[clap(long)]
        table_4: bool,

        #[clap(long)]
        table_64: bool,
    },
}

impl Xtask for Precheck {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running precheck");

        if self.command.clone().is_none_or(|c| {
            matches!(
                c,
                Commands::Setup {
                    config: _,
                    symcrypt_install_method: _,
                    symcrypt_version: _
                }
            )
        }) {
            // extract options
            let mut config_option = None;
            let mut symcrypt_install_method_option = None;
            let mut symcrypt_version_option = None;
            if let Some(Commands::Setup {
                config,
                symcrypt_install_method,
                symcrypt_version,
            }) = self.command.clone()
            {
                config_option = config;
                symcrypt_install_method_option = symcrypt_install_method;
                symcrypt_version_option = symcrypt_version;
            }

            let setup = setup::Setup {
                force: false,
                config: config_option,
                symcrypt_ubuntu_version: None,
                symcrypt_install_method: symcrypt_install_method_option,
                symcrypt_version: symcrypt_version_option,
                symcrypt_os: None,
                symcrypt_architecture: None,
            };
            setup.run(ctx.clone())?;
        }

        // Run Copyright
        if self
            .command
            .clone()
            .is_none_or(|c| matches!(c, Commands::Copyright))
        {
            let copyright = copyright::Copyright { fix: false };
            copyright.run(ctx.clone())?;
        }

        // Cargo format
        if self
            .command
            .clone()
            .is_none_or(|c| matches!(c, Commands::Fmt { skip_toolchain: _ }))
        {
            // extract skip_toolchain flag
            let mut skip_toolchain_flag = false;
            if let Some(Commands::Fmt { skip_toolchain }) = self.command.clone() {
                skip_toolchain_flag = skip_toolchain;
            }

            let fmt = fmt::Fmt {
                fix: false, // Do not fix formatting issues by default
                toolchain: if skip_toolchain_flag {
                    None
                } else {
                    Some("nightly".to_string())
                }, // Use nightly toolchain by default
            };
            fmt.run(ctx.clone())?;
        }

        // Cargo Clippy
        if self
            .command
            .clone()
            .is_none_or(|c| matches!(c, Commands::Clippy))
        {
            let clippy = clippy::Clippy {};
            clippy.run(ctx.clone())?;
        }

        // Clean release native build and run tests
        if self
            .command
            .clone()
            .is_none_or(|c| matches!(c, Commands::NativeBuildAndTest))
        {
            let cpp_test = native::NativeBuildAndTest {
                clean: true,              // clean build directory by default
                config: "Release".into(), // Use Release configuration by default
                test: true,               // Run tests as part of precheck
            };
            cpp_test.run(ctx.clone())?;
        }

        // SDK Run all mock tests
        if self
            .command
            .clone()
            .is_none_or(|c| matches!(c, Commands::MockTests))
        {
            let nextest = nextest::Nextest {
                features: Some("mock".to_string()),
                package: None,
                no_default_features: false,
                filterset: None,
            };
            nextest.run(ctx.clone())?;
        }

        #[cfg(not(target_os = "windows"))]
        {
            // SDK Run azihsm_ddi mock tests table-4
            if self.command.clone().is_none_or(|c| {
                matches!(
                    c,
                    Commands::AzihsmDdiTests {
                        table_4: true,
                        table_64: false
                    }
                )
            }) {
                let nextest = nextest::Nextest {
                    features: Some("mock,table-4".to_string()),
                    package: Some("azihsm_ddi".to_string()),
                    no_default_features: false,
                    filterset: None,
                };
                nextest.run(ctx.clone())?;
            }

            // SDK Run azihsm_ddi mock tests table-64
            if self.command.is_none_or(|c| {
                matches!(
                    c,
                    Commands::AzihsmDdiTests {
                        table_4: false,
                        table_64: true
                    }
                )
            }) {
                let nextest = nextest::Nextest {
                    features: Some("mock,table-64".to_string()),
                    package: Some("azihsm_ddi".to_string()),
                    no_default_features: false,
                    filterset: None,
                };
                nextest.run(ctx)?;
            }
        }

        log::trace!("done precheck");
        Ok(())
    }
}
