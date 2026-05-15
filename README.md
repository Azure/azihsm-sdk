# Azure Integrated HSM SDK

## Project Overview

Azure Integrated HSM (AZIHSM) SDK is a modular, cross-platform software development kit (SDK) written in Rust. This repository is home to AZIHSM SDK, its simulator, and its OpenSSL Provider.

## Project Structure

- `api/` - Core AZIHSM SDK implementation
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

The recommended way is via xtask, which selects the OpenSSL ABI version
explicitly and routes artifacts to `target/ossl-abi-<major>-<minor>/`:

```bash
# Default: OpenSSL 3.0.3
cargo xtask build

# Pin a specific OpenSSL version
cargo xtask build --openssl-version 3.5.0
```

Build specific packages using:

```bash
# Build specific packages you are modifying
cargo xtask build --package <package-name>
cargo xtask build --openssl-version 3.5.0 --package <package-name>
```

Plain `cargo build` also works — `.cargo/config.toml` sets a default
`target-dir = "target/ossl-abi-3-0"`, so the basic case needs no env vars:

```bash
cargo build --features mock                                       # default 3.0.3
CARGO_TARGET_DIR=target/ossl-abi-3-5 cargo build --features mock  # 3.5.0
```

**Use `cargo xtask build --openssl-version <ver>` when you want to be explicit
about the ABI version** — the plain form silently uses the config default,
which makes accidental wrong-version builds easier than they would be with
the explicit flag. xtask is also the only way to switch between versions
without remembering to set `CARGO_TARGET_DIR`.

## Testing

Before running any commands below, ensure you have finished the initial setup steps.

### Unit Tests

Use cargo-nextest (recommended):

```bash
# Run tests in specific packages you are modifying against simulator
cargo xtask nextest --features mock --package <package-name>
```

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

## Precheck Steps

Before running any commands below, ensure you have finished the initial setup steps.

You can run all checks (setup, build, formatting, copyright, linting, tests, code coverage etc.) against simulator with:

```bash
cargo xtask precheck --all
```

It will run all necessary checks to ensure code quality before committing. It will not auto fix linting, formatting or copyright issues.

## License

See [LICENSE](./LICENSE) for details.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
