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
cargo fmt --allExpand commentComment on line R20Resolved
cargo clippy --workspace
cargo xtask precheck
```
### Build the DDI layer
```bash
cargo build -p azi_hsm_native
```
### Build the OpenSSL Provider
```bash
cd plugins/ossl_providerExpand commentComment on line R30Resolved
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
