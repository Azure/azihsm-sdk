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

### coverage

Build and run all tests with code coverage enabled.

```bash
# Build/run tests with code coverage
cargo xtask coverage
```

### coverage-report

Using coverage data created in coverage xtask, generates a cobertura XML, JSON, and HTML report in [reporoot]/target/reports.
Also outputs a markdown line coverage summary to stdout if run locally or GITHUB_STEP_SUMMARY if run in GitHub Actions.

```bash
# Generate code coverage reports
cargo xtask coverage-report
```

## Command Details

- **precheck**: Combines setup, copyright, audit, fmt, clippy, and nextest stages for comprehensive validation
- **clippy**: Runs `cargo clippy --workspace --all-targets` with warnings treated as errors
- **fmt**: Uses `cargo fmt` to check/fix Rust code formatting
- **copyright**: Ensures all source files have proper Microsoft copyright headers
- **coverage**: Build/run all tests with code coverage enabled

## Dependencies

- CMake
- Rust toolchain with clippy and rustfmt
- xshell crate for shell operations
