// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fs;
use std::path::Path;
use std::path::PathBuf;

use clap::Parser;

use crate::Xtask;
use crate::XtaskCtx;

/// Generate register code (firmware regs + optional host bus-device emulator
/// code) from SystemRDL sources.
///
/// Two usage modes:
///
/// 1. **Curated**: `--soc uno` or `--cpu cortex_m` — uses the SDK platform's
///    own RDL + firmware reg crates. Targets are hard-coded.
///
/// 2. **Generic**: `--name <name> --rdl <path> --regs-dir <path>` (plus
///    optional `--regs-crate <name> --bus-crate <name> --devs-dir <path>`
///    for emitting bus-device emulator code). Lets downstream consumers
///    use the same code generator for their own RDL files without duplicating
///    it.
#[derive(Parser)]
pub struct Reggen {
    /// SoC name (currently only "uno"). Mutually exclusive with --name/--cpu.
    #[clap(long)]
    pub soc: Option<String>,

    /// CPU name (currently only "cortex_m"). Mutually exclusive with --name/--soc.
    #[clap(long)]
    pub cpu: Option<String>,

    /// Generic mode: peripheral set name (used in generated comments + as
    /// the schema name passed into translate). Mutually exclusive with --soc/--cpu.
    #[clap(long)]
    pub name: Option<String>,

    /// Generic mode: SystemRDL source file. Required when --name is set.
    #[clap(long)]
    pub rdl: Option<PathBuf>,

    /// Generic mode: directory to write firmware register files into.
    /// Required when --name is set.
    #[clap(long)]
    pub regs_dir: Option<PathBuf>,

    /// Generic mode: name of the firmware regs crate (used by device code
    /// `use <crate>::...`). Required when --devs-dir is set in generic mode.
    #[clap(long)]
    pub regs_crate: Option<String>,

    /// Name of the bus trait crate (used by device code
    /// `use <crate>::{BusDevice, BusError}`). Required when --devs-dir is
    /// set.
    #[clap(long)]
    pub bus_crate: Option<String>,

    /// Optional host emulator device output directory.
    #[clap(long)]
    pub devs_dir: Option<PathBuf>,

    /// Check mode: fail if generated files differ from committed files.
    #[clap(long)]
    pub check: bool,
}

#[derive(Debug)]
struct ReggenTarget {
    name: String,
    regs_crate: String,
    bus_crate: String,
    rdl_file: PathBuf,
    regs_dir: PathBuf,
}

impl Xtask for Reggen {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        let targets = self.resolve_targets(&ctx)?;

        for target in &targets {
            self.run_target(target)?;
        }

        Ok(())
    }
}

impl Reggen {
    fn resolve_targets(&self, ctx: &XtaskCtx) -> anyhow::Result<Vec<ReggenTarget>> {
        let mut targets = Vec::new();

        if let Some(soc) = &self.soc {
            if soc != "uno" {
                anyhow::bail!("unsupported SoC '{soc}' (expected 'uno')");
            }
            targets.push(ReggenTarget {
                name: soc.clone(),
                regs_crate: "azihsm_fw_uno_reg_soc".to_string(),
                bus_crate: self.bus_crate.clone().unwrap_or_default(),
                rdl_file: ctx.root.join("rdl/soc/uno.rdl"),
                regs_dir: ctx.root.join("fw/reg/soc/src"),
            });
        }

        if let Some(cpu) = &self.cpu {
            if cpu != "cortex_m" {
                anyhow::bail!("unsupported CPU '{cpu}' (expected 'cortex_m')");
            }
            targets.push(ReggenTarget {
                name: cpu.clone(),
                regs_crate: "azihsm_fw_uno_reg_cortex_m".to_string(),
                bus_crate: self.bus_crate.clone().unwrap_or_default(),
                rdl_file: ctx.root.join("rdl/cortex-m/cortex_m.rdl"),
                regs_dir: ctx.root.join("fw/reg/cortex-m/src"),
            });
        }

        if let Some(name) = &self.name {
            let rdl = self
                .rdl
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--name requires --rdl <path>"))?;
            let regs_dir = self
                .regs_dir
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--name requires --regs-dir <path>"))?;
            let regs_crate = self.regs_crate.clone().unwrap_or_default();
            let bus_crate = self.bus_crate.clone().unwrap_or_default();
            if self.devs_dir.is_some() && (regs_crate.is_empty() || bus_crate.is_empty()) {
                anyhow::bail!("--devs-dir requires --regs-crate and --bus-crate in generic mode");
            }
            targets.push(ReggenTarget {
                name: name.clone(),
                regs_crate,
                bus_crate,
                rdl_file: rdl,
                regs_dir,
            });
        }

        if targets.is_empty() {
            anyhow::bail!("Specify --soc <name>, --cpu <name>, or --name <name> --rdl <path>");
        }

        Ok(targets)
    }

    fn run_target(&self, target: &ReggenTarget) -> anyhow::Result<()> {
        log::info!("Parsing RDL: {}", target.rdl_file.display());

        let file_source = azihsm_systemrdl::FsFileSource::new();
        let root = azihsm_systemrdl::ast::Root::from_file(&file_source, &target.rdl_file)?;

        let schema = azihsm_reggen::translate::from_ast(&root, &target.name)?;
        log::info!("Found {} peripheral(s)", schema.blocks.len());

        let regs_files = azihsm_reggen::regs::generate(&schema);
        let devs_files = self
            .devs_dir
            .as_ref()
            .map(|_| azihsm_reggen::devs::generate(&schema, &target.regs_crate, &target.bus_crate));

        if self.check {
            let mut diffs = check_files(&target.regs_dir, &regs_files)?;
            if let (Some(devs_dir), Some(devs_files)) = (&self.devs_dir, &devs_files) {
                diffs += check_files(devs_dir, devs_files)?;
            }
            if diffs > 0 {
                anyhow::bail!(
                    "{} file(s) differ for '{}'. Run without --check to regenerate.",
                    diffs,
                    target.name
                );
            }
            log::info!("All generated files for '{}' are up to date.", target.name);
        } else {
            write_files(&target.regs_dir, &regs_files)?;
            if let (Some(devs_dir), Some(devs_files)) = (&self.devs_dir, &devs_files) {
                write_files(devs_dir, devs_files)?;
            }
            log::info!(
                "Generated {} register file(s){} for '{}'.",
                regs_files.len(),
                devs_files
                    .as_ref()
                    .map(|files| format!(" + {} device file(s)", files.len()))
                    .unwrap_or_default(),
                target.name,
            );
        }

        Ok(())
    }
}

fn write_files(dir: &Path, files: &[(String, String)]) -> anyhow::Result<()> {
    fs::create_dir_all(dir)?;
    for (name, content) in files {
        let path = dir.join(format!("{}.rs", name));
        fs::write(&path, content)?;
        log::info!("  Wrote: {}", path.display());
    }
    Ok(())
}

fn check_files(dir: &Path, files: &[(String, String)]) -> anyhow::Result<usize> {
    let mut diffs = 0;
    for (name, content) in files {
        let path = dir.join(format!("{}.rs", name));
        if !path.exists() {
            log::error!("Missing: {}", path.display());
            diffs += 1;
        } else {
            let existing = fs::read_to_string(&path)?;
            if existing != *content {
                log::error!("Differs: {}", path.display());
                diffs += 1;
            }
        }
    }
    Ok(diffs)
}
