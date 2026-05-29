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

### custom-openssl

Build a pinned OpenSSL 3.x release into `target/openssl-custom/<version>/`.
A temporary bridge for testing against OpenSSL versions that aren't yet
available as the container's system OpenSSL (notably 3.5.x). The install
tree is entirely workspace-local; nothing is installed to system paths.

```bash
# Install OpenSSL 3.5.4
cargo xtask custom-openssl --version 3.5.4

# Override the install prefix
cargo xtask custom-openssl --version 3.0.13 --prefix /tmp/ssl

# Rebuild even if already installed
cargo xtask custom-openssl --version 3.5.4 --force
```

After installation, point `OPENSSL_DIR` at the printed prefix so
`host_openssl::check_openssl` picks it up:

```bash
export OPENSSL_DIR=$(cargo xtask custom-openssl --version 3.5.4 | tail -1)
```

Allowlisted versions only — see `SUPPORTED_VERSIONS` in
`xtask/src/custom_openssl.rs`. Add new (version, sha256) tuples there when
needed.

### integration-tests

Run the provider integration suites (CLI, CAPI, NGINX) against the host's
OpenSSL (discovered via `host_openssl::check_openssl`: `OPENSSL_DIR`, then
`pkg-config`, then well-known prefixes).

```bash
# Run all three suites against the host's OpenSSL
cargo xtask integration-tests

# Run a single suite
cargo xtask integration-tests --suite cli
cargo xtask integration-tests --suite capi
cargo xtask integration-tests --suite nginx
```

To test against a specific pinned OpenSSL (e.g., 3.5.4), install it via
`custom-openssl` and export `OPENSSL_DIR` first.

The provider stack must be built up front: `cargo xtask build --features mock`.

#### Skipping tests that require a specific OpenSSL version

Set `AZIHSM_TEST_OPENSSL_MAJOR_MINOR` (e.g., `"3.0"` or `"3.5"`) to drive
per-suite skip conventions:

- **CAPI**: any gtest case whose name contains `_RequiresOpenssl35` is
  reported as `ignored` when the env var is `"3.0"`.
- **NGINX**: any assertion script whose filename contains
  `_requires_openssl_3_5` prints `[SKIP]` and is not executed when the
  env var is `"3.0"`.
- **CLI**: a lit `.sh` script can call `skip_below_ossl_3_5` (defined in
  `testfiles/env.sh`) near the top to exit 0 when `openssl version` is
  below 3.5.  This is a build-/runtime check independent of the env var.

`.github/workflows/provider.yml` sets `AZIHSM_TEST_OPENSSL_MAJOR_MINOR`
per job automatically.

## Command Details

- **precheck**: Combines setup, copyright, audit, fmt, clippy, and nextest stages for comprehensive validation
- **clippy**: Runs `cargo clippy --workspace --all-targets` with warnings treated as errors
- **fmt**: Uses `cargo fmt` to check/fix Rust code formatting
- **copyright**: Ensures all source files have proper Microsoft copyright headers
- **coverage**: Build/run all tests with code coverage enabled
- **custom-openssl**: Build a pinned OpenSSL release into `target/openssl-custom/<version>/`
- **integration-tests**: Run provider integration suites (CLI, CAPI, NGINX) via `--suite <name>`

## Dependencies

- CMake
- Rust toolchain with clippy and rustfmt
- xshell crate for shell operations
