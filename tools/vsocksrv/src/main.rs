// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `vsocksrv` proxies AF_VSOCK/AF_UNIX clients to an in-process `StdHsm`.
//!
//! The implementation depends on Linux-only APIs (AF_VSOCK, plus `nix`
//! socket options that are only implemented for Linux) and therefore only
//! builds and runs on Linux. On other platforms (including other Unix
//! platforms such as macOS/BSD, which lack AF_VSOCK) this binary compiles
//! to a stub that reports the limitation, so that `vsocksrv` can remain a
//! normal workspace member and participate in cross-platform builds (e.g.
//! Windows CI) without special casing.

#[cfg(target_os = "linux")]
mod unix;

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    unix::main()
}

#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("vsocksrv only supports Linux (it requires AF_VSOCK/AF_UNIX sockets)");
}
