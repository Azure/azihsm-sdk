# HSM Xtask

This directory contains automation tasks for the HSM project using the xtask pattern.

## Usage

Run tasks from the HSM root directory:

```bash
cargo xtask <command> [options]
```

## Available Commands

### precheck
Run a comprehensive set of checks including copyright, formatting, and clippy.

```bash
# Run all checks
cargo xtask precheck
```

### clippy
Run Clippy linting with strict warnings.

```bash
# Run clippy checks
cargo xtask clippy
```

### fmt
Check and fix code formatting.

```bash
# Check formatting
cargo xtask fmt

# Fix formatting issues
cargo xtask fmt --fix

# Use specific toolchain
cargo xtask fmt --toolchain stable
```

### copyright
Verify and fix copyright headers in source files.

```bash
# Check copyright headers
cargo xtask copyright

# Fix missing copyright headers
cargo xtask copyright --fix
```

### native-build-and-test (alias: nbt)
Build and test native C++ components using CMake.

```bash
# Basic build (Debug configuration)
cargo xtask nbt

# Clean build
cargo xtask nbt --clean

# Clean build and run tests
cargo xtask nbt --clean --test

# Release build
cargo xtask nbt --config Release

# Clean release build
cargo xtask nbt --clean --config Release

# Clean release build and run tests
cargo xtask nbt --clean --config Release --test
```

**Requirements:** CMake must be installed and available in PATH.

## Command Details

- **precheck**: Combines copyright, fmt, and clippy checks for comprehensive validation
- **clippy**: Runs `cargo clippy --all-targets` with warnings treated as errors
- **fmt**: Uses `cargo fmt` to check/fix Rust code formatting
- **copyright**: Ensures all source files have proper Microsoft copyright headers
- **build-cpp**: Cross-platform C++ build automation using CMake

## Dependencies

- CMake (for build-cpp command)
- Rust toolchain with clippy and rustfmt
- xshell crate for shell operations