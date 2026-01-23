# AZIHSM SDK Repository

## Project Overview
Azure Integrated HSM (AZIHSM) SDK is a modular, cross-platform software development kit (SDK) written in Rust. This repository is home to AZIHSM SDK, its simulator, and its OpenSSL Provider. The project focuses on creating secure, high-performance APIs.

## Technology Stack
- **Language**: For AZIHSM SDK and simulator: Rust (using Cargo build system), C for OpenSSL Provider, C++ for Google test integration tests
- **Build Tool**: Cargo with custom xtask automation
- **Testing Framework**: Rust unit tests for Rust code + Google test unit tests for C and C++ code. All tests including Google test have to be run with cargo-nextest (recommended)

## Project Structure
- `api/` - Core AZIHSM SDK implementation
- `api/tests/cpp/` - Google test integration tests for AZIHSM SDK C API
- `crates/` - Shared support libraries
- `ddi/` - Device Data Interface components for interacting with AZIHSM hardware
- `ddi/sim/` - AZIHSM functional simulator
- `plugins/ossl_prov/` - OpenSSL Provider implementation
- `xtask/` - Custom build and automation tasks

## Initial Setup
Before running any commands in this document for the first time, restore required dependencies using these steps:

For Linux systems, first install the following 4 Linux packages with the package manager of the distribution:
```
clang-format-18
libbsd-dev
libssl-dev
pkg-config
```

For both Linux and Windows systems, run the following to install all other required dependencies:
```bash
cargo xtask precheck --setup
```

## Build Commands
Before running any commands below, ensure you have finished the initial setup steps.

### Building
Build the project using Cargo xtask:
```bash
cargo xtask build
```

Build specific packages using:
```bash
# Build specific packages you are modifying
cargo xtask build --package <package-name>
```

## Testing
Before running any commands below, ensure you have finished the initial setup steps.

### Unit Tests
Use cargo-nextest (recommended):
```bash
# Run tests in specific packages you are modifying against simulator
cargo xtask nextest --features mock --package <package-name>
```

### Test Types
- **Unit tests**: Spread throughout crates, marked by `#[cfg(test)]` blocks
- **AZIHSM Integration tests**: Integration tests are in `ddi/lib/tests/` and `api/tests/`

## Linting and Formatting
Before running any commands below, ensure you have finished the initial setup steps.

### Required Before Each Commit
Always run formatting checks before committing:
```bash
cargo +nightly xtask fmt --fix
```
It auto fixes formatting issues. This ensures all source code follows rustfmt standards.

Always run copyright checks before committing:
```bash
cargo xtask copyright --fix
```
It auto fixes copyright issues. This ensures all source code has correct copyright headers.

## Running all of the above checks
Before running any commands below, ensure you have finished the initial setup steps.

You can run all checks (setup, build, formatting, copyright, linting, tests, code coverage etc.) against simulator with:
```bash
cargo xtask precheck --all
```
It will run all necessary checks to ensure code quality before committing. It will not auto fix linting, formatting or copyright issues.


## Code Standards

### Key Guidelines
1. Follow Rust best practices and idiomatic patterns
2. Maintain existing code structure and organization
3. Write unit tests for new functionality
4. Document public APIs and complex logic
5. Update documentation in `api/native/doc/` folder when adding features or changing behavior

### Domain-specific Guidelines
Both `api/` and `ddi/` process data from untrusted sources.

**Trust Boundaries** (critical for security):
- Code must not panic on any input
- Validate all inputs rigorously
- Ensure private keys, secrets, and sensitive data are handled securely and never logged anywhere.

When possible:
1. Avoid `unsafe` code
2. Avoid taking new external dependencies, especially those that significantly increase binary size
3. Ensure code doesn't panic across trust boundaries

## Testing Best Practices
- Thoroughly test code with unit tests whenever possible
- Add AZIHSM Integration test cases for interesting integration points
- Unit tests should be fast, isolated, and not require root/administrator access
- Mark tests requiring special setup with `#[ignore]` for manual testing
