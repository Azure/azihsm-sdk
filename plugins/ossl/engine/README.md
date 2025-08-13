AZIHSM OpenSSL engine
------------------

[[_TOC_]]

Introduction
============
This guide will walk you through setting up, building, and testing the AZIHSM OpenSSL engine.

Cloning the Repo
================
Run this command to clone the repo:

```bash
$ git clone https://msazure.visualstudio.com/DefaultCollection/One/_git/Martichoras
$ cd Martichoras
```

Building
========
### Prerequisites
Ensure the following dependencies are installed on your build machine:

1. [msrustup](https://msazure.visualstudio.com/One/_git/Martichoras?path=%2Fdocs%2Fmsrustup-setup.md) - Microsoft's proprietary version of rustup, a command line tool for installing Rust. You can follow more detailed instructions on how to setup your toolchain using msrustup here: `${REPO}\docs\msrustup-setup.md`
2. [SymCrypt](https://github.com/microsoft/SymCrypt) - The core cryptographic library used by Windows. The AZIHSM OpenSSL Engine depends on it for certain cryptographic operations.
3. Install the packages specified in the [packages](#Packages) section.
4. Ensure that OpenSSL 1.1 or OpenSSL 3.0 is installed on your machine. The system's default OpenSSL is used. OpenSSL is included by default in the Ubuntu distribution, and the development package can be installed using `libssl-dev`.

#### Packages
The following packages are required to build the engine:

```bash
$ sudo apt update && sudo apt install build-essential pkg-config libclang-dev libssl-dev ninja-build cmake
```

### Building the project
There are several options for building the engine, depending on your environment. Ensure you are in the `<REPOROOT>/plugins/ossl/engine` directory before running these commands.

#### Build for Mock device *(I want to develop/test the engine without a physical AZIHSM device)*
Run the following command:

```bash
# For Debug build
$ cargo build --features=mock

# For Release build
$ cargo build --features=mock --release
```

#### Build for Hardware *(I am working on a machine with a physical AZIHSM device)*
Run the following commands: 

```bash
# For Debug build
$ cargo build

# For Release build
$ cargo build --release
```

For debug builds, the engine will be located in `target/debug/libazihsmengine.so`. For release builds, the engine will be located in `target/release/libazihsmengine.so`.

**NOTE:** Ensure that the current git commit you have checked out when you invoke cargo build matches the release commit for the AZIHSM driver you've installed on the system. (See the test-bench README for more information.) If these do not match, you run the risk of compiling a AZIHSM OpenSSL Engine engine that expects different behavior from the AZIHSM driver.

Installation
============
To install the engine, copy the engine file from the appropriate path mentioned above to a location accessible by the operating system. You can use the system path (see below) or another path, as long as it is accessible by the application to load the engine dynamically.


### System paths for engine
On Ubuntu 22.04 and later, the default path is `/usr/lib/x86_64-linux-gnu/engines-3/`. On Ubuntu 20.04, the default path is `/usr/lib/x86_64-linux-gnu/engines-1.1/`. Replace any references to `${SYSTEMPATH}` below with the path you are using.

Using the engine with OpenSSL
=============================
There are several mechanisms to load the Engine with OpenSSL.

### Verifying the Engine loading with command line tool
OpenSSL command line tool can be used to verify if OpenSSL can find and load the Engine library.

```bash
# Make sure you use the correct path
$ openssl engine dynamic -pre SO_PATH:${SYSTEMPATH}/libazihsmengine.so -pre ID:azihsmengine -pre LOAD
```

You should see `Loaded: (azihsmengine) AZIHSM OpenSSL engine` in the output if Engine is loaded successfully. Any other errors or warnings are extraneous noise from OpenSSL and can be ignored.

### Loading in an application
Depending on the requirement, there are several ways to load the engine into application.

#### Using ENGINE APIs
Applications can load the Engine using ENGINE APIs. The following code snippet demonstrates how to load the engine in an application:

```c
ENGINE *e = ENGINE_by_id("dynamic");
ENGINE_ctrl_cmd_string(e, "SO_PATH", "${SYSTEMPATH}/libazihsmengine.so", 0);
ENGINE_ctrl_cmd_string(e, "ID", "azihsmengine", 0);
ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0);
```

#### Using Configuration file
It is possible to autoload the engine by configuring the engine-specific section in the OpenSSL configuration file. It is not recommended to modify the system's default OpenSSL configuration file (`/etc/ssl/openssl.cnf`) as this may cause problems. Instead, it is recommended to create a copy and use the copy as needed in applications.

For Ubuntu, copy the default OpenSSL configuration file to a new file and ensure it is accessible by the application:

```bash
$ sudo cp /etc/ssl/openssl.cnf /etc/ssl/openssl-azihsm.cnf
$ sudo chmod 644 /etc/ssl/openssl-azihsm.cnf
```

Next, add the following lines to the copied configuration file, updating the path to `libazihsmengine.so` as necessary:

```ini
[openssl_init]
# Add this to the existing openssl_init section
engines = engine_sect

# Add the below lines at the bottom of the file
[engine_sect]
azihsmengine = azihsmengine_sect

[azihsmengine_sect]
engine_id = azihsmengine
# Make sure you use the correct path!
dynamic_path = ${SYSTEMPATH}/libazihsmengine.so
default_algorithms = ALL
init = 1
```

To let OpenSSL load the engine using a custom configuration file, applications need set the `OPENSSL_CONF` environment variable to the path of the configuration file created in the previous step.

For example, for openssl command line tool to load the engine using the custom configuration file:

```bash
$ OPENSSL_CONF=/etc/ssl/openssl-azihsm.cnf openssl engine
```

You should see `(azihsmengine) AZIHSM OpenSSL engine` in the output if the engine was loaded correctly.

Testing
=======
### Engine unit tests
**NOTE:** The tests require the `-- --test-threads=1` flag to work correctly and you will get test failures without them. For more information on other flags, see the [`cargo test`](https://doc.rust-lang.org/cargo/commands/cargo-test.html) documentation.

To build and run Rust unit tests:

```bash
$ cd plugins/ossl/engine
$ cargo test --features=mock -- --test-threads=1
```

### Engine Catch2 Functional tests
To run Catch2 tests, see the [README.md](tests/README.md) file in the `tests` subdirectory.

Code Coverage
=============
### Code coverage for unit tests
To get code coverage for the unit tests, run the following from the `plugins/ossl/engine` directory:

```bash
# Setup lcov and cargo-llvm-cov
$ sudo apt install lcov
$ cargo install cargo-llvm-cov

# Run the tests
$ cargo llvm-cov -p azihsmengine --ignore-filename-regex='api/.*$' --features=mock --html --output-dir target/html-out -- --test-threads=1
```

The HTML results of the code coverage checks will be in `target/html-out/html`.

### Code coverage for Catch2 tests
You must set up the Catch2 tests before getting code coverage information. See [tests/README.md](the tests README) for more information.

Note: The code coverage tool runs on the debug build of the Engine library, compiled for mock device.

To get code coverage for the Catch2 tests, run the following from `plugins/ossl/engine`:

```bash
# Setup cargo-binutils and lcov
$ sudo apt install lcov
$ cargo install cargo-binutils rustfilt
$ hash -r

# Build with profiling data
$ cargo clean
$ RUSTFLAGS="-C instrument-coverage" cargo build --features=mock

# Go to the unit tests directory (see test setup instructions)
$ cd tests/bld_test_engine

# Run the coverage target
$ ninja coverage
```

*NOTE: a lot of profraw files may be created by the `cargo build` step in `plugins/ossl/engine`. They can be safely removed.*

The HTML results of the Catch2 code coverage checks will be in `tests/bld_test_engine/html-out/`, which can be viewed in a browser by opening the `index.html` file. 

Debugging
=========
Debugging can be done with `gdb`. For example, to debug the Catch2 unit tests:

```bash
$ gdb ./AZIHSMEngineTests
```

Using `run -a` is recommended to stop the tests when the first failure occurs.
