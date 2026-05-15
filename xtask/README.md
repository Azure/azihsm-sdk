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

### setup

Install build dependencies. On Linux, also installs OpenSSL into the ABI tree
(`target/ossl-abi-<major>-<minor>/openssl/`).

```bash
# Install OpenSSL 3.0.3 (default version)
cargo xtask setup

# Install OpenSSL 3.5.0
cargo xtask setup --openssl-version 3.5.0

# Skip OpenSSL install (e.g., when bringing your own via OPENSSL_DIR)
cargo xtask setup --skip-openssl
```

### build

Build the workspace. On Linux, routes artifacts to the ABI-versioned target tree
(`target/ossl-abi-<major>-<minor>/`) so multiple OpenSSL ABI versions can be
cached side by side. No env vars needed.

```bash
# Build the whole workspace for OpenSSL 3.0.3 (default)
cargo xtask build --features mock

# Build for OpenSSL 3.5.0
cargo xtask build --openssl-version 3.5.0 --features mock

# Build only the provider crates (faster than full workspace)
cargo xtask build --openssl-version 3.0.3 --package azihsm_ossl_provider --features mock
cargo xtask build --openssl-version 3.0.3 --package azihsm_api_native   --features mock
```

The whole workspace covers both `azihsm_api_native` and `azihsm_ossl_provider`
automatically — naming the package is only useful for targeted/faster builds.
Omit `--features mock` to build against real hardware.

### integration-tests

Run provider integration tests (CLI, C API, NGINX). Builds the provider on
demand into the ABI tree before running tests.

```bash
# Run against OpenSSL 3.0.3 (default)
cargo xtask integration-tests

# Run against OpenSSL 3.5.0
cargo xtask integration-tests --openssl-version 3.5.0
```

When `OPENSSL_DIR` is set, the `--openssl-version` flag is ignored and the
existing installation is used as-is. See `plugins/ossl_prov/README.md` for
environment variable details.

## Command Details

- **setup**: Installs build deps and (Linux) OpenSSL.  Honours `--openssl-version`.
- **build**: Wraps `cargo build` with the right `CARGO_TARGET_DIR` for the chosen OpenSSL ABI version.
- **integration-tests**: Runs CLI, C API, and NGINX provider integration tests. Builds the provider on demand.
- **precheck**: Combines setup, copyright, audit, fmt, clippy, and nextest stages for comprehensive validation
- **clippy**: Runs `cargo clippy --workspace --all-targets` with warnings treated as errors
- **fmt**: Uses `cargo fmt` to check/fix Rust code formatting
- **copyright**: Ensures all source files have proper Microsoft copyright headers
- **coverage**: Build/run all tests with code coverage enabled

## Dependencies

- CMake
- Rust toolchain with clippy and rustfmt
- xshell crate for shell operations
