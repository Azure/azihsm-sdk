// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Aggregate pre-commit checks for the uno firmware workspace.
//!
//! By default every stage runs; pass one or more `--<stage>` flags to run a
//! subset. The `--skip-audit` flag opts out of `cargo audit` (useful for
//! offline runs).

use clap::Parser;

use crate::Xtask;
use crate::XtaskCtx;

#[derive(Parser, Debug, Clone, Default)]
struct Stage {
    /// Run setup.
    #[clap(long)]
    setup: bool,
    /// Run reggen --check.
    #[clap(long)]
    reggen: bool,
    /// Run fmt checks (firmware).
    #[clap(long)]
    fmt: bool,
    /// Run clippy checks (firmware).
    #[clap(long)]
    clippy: bool,
    /// Run copyright header check.
    #[clap(long)]
    copyright: bool,
    /// Run cargo audit (firmware).
    #[clap(long)]
    audit: bool,
    /// Run release build (firmware).
    #[clap(long)]
    build: bool,
}

impl Stage {
    fn any(&self) -> bool {
        self.setup
            || self.reggen
            || self.fmt
            || self.clippy
            || self.copyright
            || self.audit
            || self.build
    }

    fn all() -> Self {
        Self {
            setup: true,
            reggen: true,
            fmt: true,
            clippy: true,
            copyright: true,
            audit: true,
            build: true,
        }
    }
}

/// Run pre-commit checks across the uno firmware workspace.
#[derive(Parser)]
#[clap(about = "Run all pre-commit checks (setup, fmt, clippy, copyright, audit, build, reggen)")]
pub struct Precheck {
    #[clap(flatten)]
    stage: Stage,
    /// Skip `cargo audit` (useful offline).
    #[clap(long)]
    skip_audit: bool,
}

impl Xtask for Precheck {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        let mut errors: Vec<(&str, anyhow::Error)> = Vec::new();

        // No flags = run everything.
        let stage = if self.stage.any() {
            self.stage
        } else {
            Stage::all()
        };

        if stage.setup {
            log::info!("=== setup ===");
            if let Err(e) = (crate::setup::Setup {
                force: false,
                config: None,
                skip_audit: self.skip_audit,
            })
            .run(ctx.clone())
            {
                errors.push(("setup", e));
            }
        }

        if stage.reggen {
            log::info!("=== reggen --check (uno) ===");
            if let Err(e) = (crate::reggen::Reggen {
                soc: Some("uno".to_string()),
                cpu: None,
                name: None,
                rdl: None,
                regs_dir: None,
                regs_crate: None,
                bus_crate: None,
                devs_dir: None,
                check: true,
            })
            .run(ctx.clone())
            {
                errors.push(("reggen uno", e));
            }

            log::info!("=== reggen --check (cortex-m) ===");
            if let Err(e) = (crate::reggen::Reggen {
                soc: None,
                cpu: Some("cortex_m".to_string()),
                name: None,
                rdl: None,
                regs_dir: None,
                regs_crate: None,
                bus_crate: None,
                devs_dir: None,
                check: true,
            })
            .run(ctx.clone())
            {
                errors.push(("reggen cortex-m", e));
            }
        }

        if stage.fmt {
            log::info!("=== fmt (firmware) ===");
            if let Err(e) = (crate::fmt::Fmt { fix: false }).run(ctx.clone()) {
                errors.push(("fmt", e));
            }
        }

        if stage.clippy {
            log::info!("=== clippy (firmware) ===");
            if let Err(e) = (crate::clippy::Clippy {}).run(ctx.clone()) {
                errors.push(("clippy", e));
            }
        }

        if stage.copyright {
            log::info!("=== copyright ===");
            if let Err(e) = (crate::copyright::Copyright { fix: false }).run(ctx.clone()) {
                errors.push(("copyright", e));
            }
        }

        if stage.audit && !self.skip_audit {
            log::info!("=== audit (firmware) ===");
            if let Err(e) = (crate::audit::Audit {}).run(ctx.clone()) {
                errors.push(("audit", e));
            }
        }

        if stage.build {
            log::info!("=== build (firmware) ===");
            if let Err(e) = (crate::build::Build {
                features: None,
                no_default_features: false,
            })
            .run(ctx.clone())
            {
                errors.push(("build", e));
            }
        }

        if errors.is_empty() {
            log::info!("All prechecks passed!");
            Ok(())
        } else {
            for (name, err) in &errors {
                log::error!("{name}: {err:#}");
            }
            anyhow::bail!("{} precheck(s) failed", errors.len());
        }
    }
}
