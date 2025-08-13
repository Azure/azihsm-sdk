# AZIHSM Key Storage Provider (KSP)

[[_TOC_]]

## Getting Started
This guide will walk you through setting up, building, and testing the AZIHSM-KSP (Azure Integraed HSM Key Storage Provider).

## Prerequisites

Ensure the following are installed on your machine:

1. [msrustup](https://eng.ms/docs/more/languages-at-microsoft/rust/articles/gettingstarted/install/msrustup) - Microsoft's proprietary version of `rustup`, a command line tool for installing Rust.
    You can follow more detailed instructions on how to setup your toolchain using msrustup here: `${REPO}\docs\msrustup-setup.md`
2. [Rust](https://www.rust-lang.org/tools/install) - The Rust programming language.
3. [Powershell](https://github.com/Powershell/Powershell/releases) - Version 7.4.4.4 or higher is preferable (X64 version, for most test machines)
4. [Strawberry perl](https://strawberryperl.com/) - Required for building OpenSSL. (Download the full MSI, not the portable installation).
5. [Cryptographic Provider Development Kit](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal) - Necessary for developing cryptographic providers on Windows.
6. [SymCrypt](https://github.com/microsoft/SymCrypt) - The core cryptographic library for Windows. The AZIHSM-KSP depends on it for certain cryptographic operations.

## Building the project

To build the AZIHSM-KSP, you have a few options depending on what kind of
environment you are building for. To run these comamnds, make sure you are in
the KSP project folder (e.g., `plugins\ksp`).

### Debug Build (*I want to develop/test the AZIHSM-KSP without a physical device*)

Use the `mock` feature to have the AZIHSM-KSP DLL built with the "mock" device included in the binary:

```bash
cargo build --features mock,use-symcrypt,table-4
```

The "mock" device provides a way for the KSP to interact with a fake AZIHSM
device. This is great for development, because you do not need to be working on
a machine that has a physical AZIHSM hardware device installed.

### Hardware Build (*I am working on a machine with a physical AZIHSM device*)

To build a KSP DLL that is compatible with the physical AZIHSM device, build
without the `mock` feature:

```bash
cargo build --features use-symcrypt

# Build in release mode:
cargo build --release --features use-symcrypt
```

**NOTE:** Take care to ensure that the current git commit you have checked out
when you invoke `cargo build` matches the release commit for the AZIHSM
drivers you've installed on the system. (See [the test-bench
README](../../test-bench/readme.md) for more information.) If these do not
match, you run the risk of compiling a AZIHSM-KSP DLL that expects different
behavior from the AZIHSM drivers.

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

    cargo test --release --features use-symcrypt --no-run

### Running the tests

#### Running Individual Test Binaries

Each test binary is generated in .exe format and is available in the target directory `target/debug/deps` subdirectory. To execute an individual test, simply run the corresponding .exe file directly.

    .\Example_test.exe

#### Running All Tests at Once

To run all the test binaries, you can use the following command. This will iterate over all .exe files matching the pattern test_*.exe and execute each test sequentially.

    Forfiles /m test_*.exe /c "cmd /c @file --test-threads=1"

### Debugging the Provider

Debugging the provider can be done with the [Windows
Debugger](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/)
(see the debugger reference
[here](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-reference)).

To set your PowerShell environment up for debugging, run the
[`setup-env.ps1`](./setup-env.ps1) script:

`powershell
./setup-env.ps1 debug
`

Once done, you can invoke `windbg` on the command-line, followed by your
program arguments, to launch the debugger. For example, to run a KSP test in
the debugger:

`powershell
windbg .\target\debug\deps\test_secure_import_aes_key-957b90e3d170283b.exe
`
