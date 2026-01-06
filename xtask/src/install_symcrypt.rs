// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run install symcrypt

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::Xtask;
use crate::XtaskCtx;

#[cfg(not(target_os = "windows"))]
const UBUNTU_VER_DEFAULT: &str = "22.04";

/// Xtask to run install symcrypt
#[derive(Parser)]
#[clap(about = "Install symcrypt")]
pub struct InstallSymcrypt {
    /// Override Ubuntu version to install symcrypt for
    #[clap(long)]
    pub ubuntu_version: Option<String>,
    /// Installation method ("github" or "nuget")
    #[clap(long)]
    pub install_method: Option<String>,
    /// SymCrypt version string to pull from either NuGet or GitHub
    #[clap(long)]
    pub symcrypt_version: Option<String>,
    /// OS to install SymCrypt for
    #[clap(long)]
    pub os: Option<String>,
    /// Architecture to install SymCrypt for
    #[clap(long)]
    pub architecture: Option<String>,
}

impl Xtask for InstallSymcrypt {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running install symcrypt");

        let sh = Shell::new()?;

        #[cfg(target_os = "windows")]
        {
            let _install_method_str = self.install_method.unwrap_or_else(|| "nuget".to_string());
            let symcrypt_version = self
                .symcrypt_version
                .unwrap_or_else(|| "103.10.0-b39181fb-129971309".to_string());
            let os = self.os.unwrap_or_else(|| "windows".to_string());
            let arch = self
                .architecture
                .unwrap_or_else(|| "amd64|x64|x86_64|x86-64".to_string());
            cmd!(
                sh,
                "powershell -File .pipelines/scripts/install-symcrypt.ps1 -SymcryptVersion {symcrypt_version} -SymcryptOS {os} -SymcryptArchitecture {arch}"
            )
            .quiet()
            .run()?;
        }
        #[cfg(not(target_os = "windows"))]
        {
            cmd!(sh, "chmod +x .pipelines/scripts/install-symcrypt.sh")
                .quiet()
                .run()?;

            let ubuntu_version = self.ubuntu_version.unwrap_or_else(|| {
                sh.var("UBUNTU_VER")
                    .ok()
                    .unwrap_or_else(|| UBUNTU_VER_DEFAULT.to_string())
            });

            cmd!(
                sh,
                ".pipelines/scripts/install-symcrypt.sh {ubuntu_version}"
            )
            .quiet()
            .run()?;
        }

        log::trace!("done install symcrypt");
        Ok(())
    }
}
