// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `vsocksrv` proxies AF_VSOCK/AF_UNIX clients to an in-process `StdHsm`.
//!
//! The implementation depends on Unix-only APIs (AF_VSOCK, `nix` socket
//! options, etc.) and therefore only builds and runs on Unix platforms. On
//! other platforms this binary compiles to a stub that reports the
//! limitation, so that `vsocksrv` can remain a normal workspace member and
//! participate in cross-platform builds (e.g. Windows CI) without special
//! casing.

#[cfg(unix)]
mod unix;

#[cfg(unix)]
fn main() -> anyhow::Result<()> {
    unix::main()
}

#[cfg(not(unix))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("vsocksrv only supports Unix platforms (it requires AF_VSOCK/AF_UNIX sockets)");
}
