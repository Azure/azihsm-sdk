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

Build and run all tests with code coverage enabled. Generates a cobertura XML, JSON, and HTML report in [reporoot]/target/reports.

```bash
# Build/run tests with code coverage and generate reports
cargo xtask coverage
```

### integration-tests

Run provider integration tests (CLI, C API, NGINX). Requires a custom OpenSSL build.

```bash
# Run against default OpenSSL version (3.0.3)
cargo xtask integration-tests

# Run against a specific version
cargo xtask integration-tests --openssl-version 3.5.0
```

When `OPENSSL_DIR` is set, the `--openssl-version` flag is ignored and the
existing installation is used as-is. See `plugins/ossl_prov/README.md` for
environment variable details.

## Command Details

- **integration-tests**: Runs CLI, C API, and NGINX provider integration tests. Resolves OpenSSL via `OPENSSL_DIR` or `--openssl-version`
- **precheck**: Combines setup, copyright, audit, fmt, clippy, and nextest stages for comprehensive validation
- **clippy**: Runs `cargo clippy --workspace --all-targets` with warnings treated as errors
- **fmt**: Uses `cargo fmt` to check/fix Rust code formatting
- **copyright**: Ensures all source files have proper Microsoft copyright headers
- **coverage**: Build/run all tests with code coverage enabled

## Dependencies

- CMake
- Rust toolchain with clippy and rustfmt
- xshell crate for shell operations
