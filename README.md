# azihsm-sdk

The SDK is designed as the client‑side software stack that applications or crypto providers use to talk to the Azure Integrated HSM (AziHSM) device. The azihsm‑sdk is built in Rust as a cross‑platform cryptographic access layer for the Azure Integrated HSM, dynamically linking SymCrypt for missing public‑key crypto, and providing consumption surfaces for NCrypt (Windows), OpenSSL (Linux), and the DDI device interface; its build system compiles Rust crates, integrates native dependencies, produces provider modules and KSP binaries, and is run through GitHub CI with linting, formatting, and cross‑arch builds including ARM64.

## Build Steps
The repo has multiple components:

/api — Native API
/crates — Supporting Rust crates
/ddi — Device driver interface bindings
/plugins/ossl_provider — OpenSSL provider
/xtask — Developer automation

### To build everything:
```bash
cargo build --workspace --all-targets
```
### Run formatting, linting, code hygiene:  
```bash
cargo fmt --all
cargo clippy --workspace
cargo xtask precheck
```
### Build the DDI layer
```bash
cargo build -p azi_hsm_native
```
### Build the OpenSSL Provider
```bash
cd plugins/ossl_provider
cargo build --release
```
### Build the Windows KSP (Key Storage Provider)
```bash
cargo build -p azi_hsm_ksp --release
```

### Build Platform‑Specific Outputs:
#### Windows x64:
- ```bash
  cargo build --release --target x86_64-pc-windows-msvc'
  ```
#### Windows ARM64:
- ```bash
  cargo build --release --target aarch64-pc-windows-msvc
  ```
#### Linux:
```bash
cargo build --release --target x86_64-unknown-linux-gnu
```

### Run Tests:
- ```bash
  cargo test --workspace
  ```

# License
See LICENSE.md for details.

# Contributing
All contributors must comply with Microsoft’s Open Source Release Policy.

# Trademarks
This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow Microsoft’s Trademark & Brand Guidelines. Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party’s policies.
