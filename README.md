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

## Tracing

The SDK emits structured traces through the `Microsoft.Azure.IHSM` provider
with keyword `1`. On Windows, traces are emitted through ETW. On Linux, traces
are emitted through the
[user_events](https://docs.kernel.org/trace/user_events.html) subsystem.

When native tracing is initialized, the SDK emits an `INFO` event confirming the
native tracing provider was registered, followed by one sample event at each
`tracing` level: `ERROR`, `WARN`, `INFO`, `DEBUG`, and `TRACE`. The sample
events have `sample=true` and are intended only for testing. The SDK also emits
an `INFO` sample named `AZIHSM sample parameterized event` with structured
fields such as `operation`, `request_id`, `partition_count`, `duration_ms`, and
`success`.

### Windows ETW

Run the following from an elevated PowerShell or command prompt:

```powershell
# Start an ETW session for all AZIHSM events at keyword 1 and verbose level.
logman start AZIHSMTrace -ets -p Microsoft.Azure.IHSM 0x1 0x5 -o azihsm.etl

# Run your application.
<your-application>

# Stop the ETW session.
logman stop AZIHSMTrace -ets
```

Open `azihsm.etl` with Windows Performance Analyzer or PerfView to inspect the
recorded events.

### Linux user_events prerequisites

`user_events` requires kernel >= 6.4, or a back-ported build that enables
`CONFIG_USER_EVENTS`. Verify support:

```bash
ls /sys/kernel/tracing/user_events_data   # should exist
```

### Collecting Linux traces with `perf`

```bash
# 1. List available user_events tracepoints registered by the SDK.
sudo perf list 'user_events:*'

# 2. Record all events from the Microsoft.Azure.IHSM provider.
sudo perf record -e 'user_events:*' -a -- <your-application>

# 3. View the recorded trace.
sudo perf script
```

### Collecting Linux traces with `trace-cmd`

```bash
# Record.
sudo trace-cmd record -e 'user_events' <your-application>

# View.
trace-cmd report
```

### Collecting Linux traces via tracefs manually

```bash
# Enable the events.
echo 1 | sudo tee /sys/kernel/tracing/events/user_events/enable

# Start reading.
sudo cat /sys/kernel/tracing/trace_pipe &

# Run your application.
<your-application>

# Disable when done.
echo 0 | sudo tee /sys/kernel/tracing/events/user_events/enable
```

## License

See [LICENSE](./LICENSE) for details.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the fork-and-pull workflow and step-by-step PR
submission guide.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
