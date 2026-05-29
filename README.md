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

## Precheck Steps

Before running any commands below, ensure you have finished the initial setup steps.

You can run all checks (setup, build, formatting, copyright, linting, tests, code coverage etc.) against simulator with:

```bash
cargo xtask precheck --all
```

It will run all necessary checks to ensure code quality before committing. It will not auto fix linting, formatting or copyright issues.

## CI Workflows

Two GitHub Actions workflows live under `.github/workflows/`:

- [`rust.yml`](.github/workflows/rust.yml) — runs on every push / PR / merge
  group. SDK-only: copyright, audit, fmt, clippy, mock tests (table-4 /
  table-64 / tbor-emu), coverage, Windows build. Does not install OpenSSL
  or run the provider.
- [`provider.yml`](.github/workflows/provider.yml) — heavy provider +
  OpenSSL integration. Two jobs (`openssl-3-0` on Ubuntu 22.04 pinned to
  OpenSSL 3.0.13, `openssl-3-5` on Ubuntu 24.04 pinned to OpenSSL 3.5.4).
  Triggered only by `workflow_dispatch`; designed to be run locally via
  [`act`](https://github.com/nektos/act) (see below) and intended as the
  blueprint for a future nightly CI run.

### Running `provider.yml` locally with `act`

One-time setup: install [`act`](https://github.com/nektos/act/#installation),
ensure Docker is up, and pull the runner images. The default `act` image
(`node:16-bullseye-slim`) is too small — it has no `sudo`/`apt`, so the
apt-install step would fail immediately. Use the matching
[`catthehacker/ubuntu`](https://github.com/catthehacker/docker_images)
images that ship a real Ubuntu userland:

```bash
docker pull catthehacker/ubuntu:act-22.04
docker pull catthehacker/ubuntu:act-24.04
```

Then run a job, mapping each `runs-on:` value with `-P`:

```bash
act --reuse -W .github/workflows/provider.yml -j openssl-3-0 \
  -P ubuntu-22.04=catthehacker/ubuntu:act-22.04 \
  -P ubuntu-24.04=catthehacker/ubuntu:act-24.04

act --reuse -W .github/workflows/provider.yml -j openssl-3-5 \
  -P ubuntu-22.04=catthehacker/ubuntu:act-22.04 \
  -P ubuntu-24.04=catthehacker/ubuntu:act-24.04
```

`--reuse` keeps the container across invocations so the cold install
(rustup install, dev-tool `cargo install`s, custom OpenSSL build from
source — together ~10–15 min the first time) does not repeat.

Each job sets `AZIHSM_TEST_OPENSSL_MAJOR_MINOR` (e.g., `"3.0"` or `"3.5"`)
so the test suites can skip cases that require a different OpenSSL
major.minor — see [xtask/README.md](xtask/README.md#integration-tests)
for the skip conventions used by the CLI, CAPI, and NGINX harnesses.

Steps in `provider.yml` marked `act-compat:` exist solely so the
workflow runs under `act`; they are idempotent no-ops on GitHub-hosted
runners (which come with Rust, `xxd`, etc. preinstalled).

### Why each job pins its OpenSSL version (and how that disappears later)

`provider.yml` calls `cargo xtask custom-openssl --version <X.Y.Z>` in
each job to install a workspace-local OpenSSL into
`target/openssl-custom/<version>/`, then exports `OPENSSL_DIR` to point
there. This is a **temporary bridge**: until Ubuntu LTS ships OpenSSL
3.5 as system, the openssl-3-5 job has no other way to test 3.5
features. The openssl-3-0 job pins to 3.0.13 (matching what Ubuntu 24.04
ships) so the eventual switch to system OpenSSL is uneventful.

The pinned-install layer is bracketed with `# === TEMPORARY ===`
markers in each job. Deleting the bracketed block per job reverts that
job to system OpenSSL via `host_openssl::check_openssl`'s well-known
prefix scan (`/usr`, `/usr/local`, …).

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
