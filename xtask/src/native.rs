// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to build the C++ components

use std::path::Path;

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to build the C++ components
#[derive(Parser)]
#[clap(about = "Build and run C++ components using CMake")]
pub struct NativeBuildAndTest {
    /// Clean build directory before building
    #[clap(long)]
    pub clean: bool,

    /// Build configuration (Debug/Release)
    #[clap(long, default_value = "Debug")]
    pub config: String,

    /// Build and run tests after building
    #[clap(long)]
    pub test: bool,
}

impl Xtask for NativeBuildAndTest {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running build-cpp");

        // The workspace root is the Martichoras root, cpp is under hsm/cpp
        let mut cpp_dir = ctx.root.clone();
        cpp_dir.extend(["api", "cpp"]);
        let build_dir = cpp_dir.join("build");

        // Verify cpp directory exists
        if !cpp_dir.exists() {
            anyhow::bail!("C++ directory not found: {}", cpp_dir.display());
        }

        // Clean build directory if requested
        if self.clean && build_dir.exists() {
            log::info!("Cleaning build directory: {}", build_dir.display());
            std::fs::remove_dir_all(&build_dir)?;
        }

        // Create build directory
        if !build_dir.exists() {
            log::info!("Creating build directory: {}", build_dir.display());
            std::fs::create_dir_all(&build_dir)?;
        }

        // Check if CMake is available
        self.check_cmake_available()?;

        // Run CMake configure
        self.run_cmake_configure(&cpp_dir, &build_dir)?;

        // Run CMake build
        self.run_cmake_build(&build_dir)?;

        // Run tests if requested
        if self.test {
            self.run_tests(&build_dir)?;
        }

        log::trace!("done build-cpp");
        Ok(())
    }
}

impl NativeBuildAndTest {
    /// Check if CMake is available in the system
    fn check_cmake_available(&self) -> anyhow::Result<()> {
        log::debug!("Checking if CMake is available");

        let sh = Shell::new()?;

        match cmd!(sh, "cmake --version").quiet().read() {
            Ok(output) => {
                let version = output.lines().next().unwrap_or("").trim();
                log::info!("Found CMake: {}", version);
                Ok(())
            }
            Err(_) => {
                let install_msg = if cfg!(target_os = "windows") {
                    "Please download and install CMake from https://cmake.org/download/"
                } else {
                    "Please install CMake using your package manager (e.g., 'sudo apt install cmake' or 'brew install cmake')"
                };
                anyhow::bail!("CMake not found in PATH. {}", install_msg);
            }
        }
    }

    /// Run CMake configure step
    fn run_cmake_configure(&self, cpp_dir: &Path, build_dir: &Path) -> anyhow::Result<()> {
        log::info!("Configuring CMake project...");
        log::debug!(
            "Running: cmake {} (from {})",
            cpp_dir.display(),
            build_dir.display()
        );

        let sh = Shell::new()?;
        sh.change_dir(build_dir);

        let config_arg = format!("-DCMAKE_BUILD_TYPE={}", self.config);

        // Add platform-specific configurations
        if cfg!(target_os = "windows") {
            log::debug!("Configuring for Windows build");
            cmd!(sh, "cmake .. {config_arg} -DBUILD_TESTING=ON").run()?;
        } else {
            log::debug!("Configuring for Linux build");
            cmd!(sh, "cmake .. {config_arg} -DBUILD_TESTING=ON").run()?;
        }

        log::info!("CMake configuration completed successfully");
        Ok(())
    }

    /// Run CMake build step
    fn run_cmake_build(&self, build_dir: &Path) -> anyhow::Result<()> {
        log::info!("Building C++ project...");

        let sh = Shell::new()?;
        sh.change_dir(build_dir);

        let config = &self.config;

        // Add platform-specific build options
        if cfg!(target_os = "windows") {
            log::debug!("Using Windows build command: cmake --build .");
            cmd!(sh, "cmake --build . --config {config}").run()?;
        } else {
            log::debug!("Using Linux build command with make");
            cmd!(sh, "cmake --build . --config {config}").run()?;
        }

        log::info!("C++ build completed successfully");
        log::info!("Build artifacts are located in: {}", build_dir.display());

        Ok(())
    }

    /// Run C++ tests using CTest
    fn run_tests(&self, build_dir: &Path) -> anyhow::Result<()> {
        log::info!("Running C++ tests using CTest...");

        let sh = Shell::new()?;
        sh.change_dir(build_dir);

        // Debug: List what's in the build directory
        log::debug!("Contents of build directory:");
        if let Ok(entries) = std::fs::read_dir(build_dir) {
            for entry in entries {
                if let Ok(entry) = entry {
                    log::debug!("  {}", entry.path().display());
                }
            }
        }

        let config = &self.config;

        // Use CTest which knows how to find and run the tests
        log::info!("Running CTest in directory: {}", build_dir.display());

        if cfg!(target_os = "windows") {
            // On Windows, specify the configuration
            cmd!(sh, "ctest --output-on-failure --verbose -C {config}").run()?;
        } else {
            // On Linux/Unix
            cmd!(sh, "ctest --output-on-failure --verbose").run()?;
        }

        log::info!("All native tests passed successfully");
        Ok(())
    }
}
