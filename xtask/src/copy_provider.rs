// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to copy the OpenSSL provider .so to target directory

use clap::Parser;
use std::fs;
use std::time::SystemTime;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to copy provider .so
#[derive(Parser)]
#[clap(about = "Copy OpenSSL provider .so to target directory")]
pub struct CopyProvider {
    /// Build in release mode
    #[clap(long)]
    pub release: bool,
}

impl Xtask for CopyProvider {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("copying provider .so");

        let profile = if self.release { "release" } else { "debug" };
        let build_parent = ctx.root.join("target").join("debug").join("build");

        // Find all azihsm_provider.so files
        let mut so_files = Vec::new();

        if let Ok(entries) = fs::read_dir(&build_parent) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir()
                    && path.file_name().map_or(false, |n| {
                        n.to_string_lossy().starts_with("azishm_ossl_provider-")
                    })
                {
                    let so_path = path.join("out").join("build").join("azihsm_provider.so");
                    if so_path.exists() {
                        so_files.push(so_path);
                    }
                }
            }
        }

        // Find the most recently modified .so
        let latest_so = so_files.into_iter().max_by_key(|path| {
            path.metadata()
                .and_then(|m| m.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH)
        });

        if let Some(source) = latest_so {
            let dest = ctx
                .root
                .join("target")
                .join(profile)
                .join("azihsm_provider.so");

            // Ensure destination directory exists
            if let Some(dest_dir) = dest.parent() {
                fs::create_dir_all(dest_dir)?;
            }

            fs::copy(&source, &dest)?;
            println!(
                "Copied {} to target/{}/azihsm_provider.so",
                source.display(),
                profile
            );
            log::trace!("done copying provider .so");
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Could not find azihsm_provider.so in CMake build output"
            ))
        }
    }
}
