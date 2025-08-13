## Getting Started
This guide will walk you through setting up, building, and testing the AZIHSM-KSP (Azure Integrated HSM Key Storage Provider).

## Prerequisites
Ensure the following are installed on your machine:
1. [Rust](https://www.rust-lang.org/tools/install) - The Rust programming language.
2. [Strawberryperl](https://strawberryperl.com/) - Required for building OpenSSL.
3. [Cryptographic Provider Development Kit](https://www.microsoft.com/en-us/download/details.aspx?id=30688/) - Necessary for developing cryptographic providers on Windows.

## Building the project
### Debug Build
To build the AZIHSM-KSP in debug mode for the mock device, run the following command:

    cargo build --features mock,table-4

To build the AZIHSM-KSP in debug mode for the physical device, run the following command:

    cargo build

### Release Build
To build the AZIHSM-KSP in release mode for the mock device, run the following command:

    cargo build --release --features mock,table-4

To build the AZIHSM-KSP in release mode for the physical device, run the following command:

    cargo build --release

## Installing the provider
Once the project has been successfully built, follow these steps to install the AZIHSM-KSP provider:

1. **Copy the DLL:** Move the built binary (azihsmksp.dll) to the C:\Windows\System32 directory on the target machine.

2. **Register the DLL:** Use the regsvr32 utility to register the DLL.

### Register the Provider
To register the AZIHSM-KSP provider, run the following command:

    regsvr32 c:\windows\system32\azihsmksp.dll

### Unregister the Provider
To unregister the AZIHSM-KSP provider, run the following command:

    regsvr32 /u c:\windows\system32\azihsmksp.dll

## Building and Running the tests

### Building the tests
To build the AZIHSM-KSP tests, run the following command from tests directory:

    cargo test --release --no-run

### Running the tests
#### Running Individual Test Binaries
Each test binary is generated in .exe format and is available in the target directory. To execute an individual test, simply run the corresponding .exe file directly.

    .\Example_test.exe

#### Running All Tests at Once
You can use cargo test runner or nextest.

Also see [build-run.md](docs\build-run.md)

```bash
# Use nextest to run tests in parallel
cargo nextest run --features <fill the same set of features used in cargo build>
# or, this is much slower
cargo test --features <fill the same set of features used in cargo build> -- --test-threads=1
```
