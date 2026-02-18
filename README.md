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

## Precheckin Steps
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
