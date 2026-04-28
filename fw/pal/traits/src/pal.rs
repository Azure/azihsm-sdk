// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM platform abstraction layer trait.

use super::*;

/// The core trait that all HSM platform implementations must implement.
///
/// Bundles all PAL sub-traits into a single bound.  A platform
/// implementation provides hardware-specific behavior behind this
/// common interface.
///
/// ## Supertraits
///
/// | Trait | Purpose |
/// |-------|---------|
/// | [`HsmIoController`] | I/O submission and completion |
/// | [`HsmGdmaController`] | Host↔device memory copies |
/// | [`HsmPartitionManager`] | Partition lifecycle queries |
/// | [`HsmPartitionLock`] | Per-partition async mutex for DDI handlers |
/// | [`HsmCertStore`] | Per-partition certificate chains |
/// | [`HsmSessionManager`] | Session allocation (vault-backed) |
/// | [`HsmVault`] | Key storage with firmware capacity emulation |
/// | [`HsmCrypto`] | Cryptographic operations (7 sub-traits) |
pub trait HsmPal:
    HsmIoController
    + HsmGdmaController
    + HsmPartitionManager
    + HsmPartitionLock
    + HsmCertStore
    + HsmSessionManager
    + HsmVault
    + HsmCrypto
    + Default
{
    /// Initializes the platform.
    ///
    /// Must be called before [`run`](Self::run). Performs any one-time hardware
    /// or driver setup required by the platform.
    fn init(&self);

    /// Runs the main platform event loop.
    ///
    /// This is an async entry point that drives the platform's ongoing
    /// operation. It returns when the platform has completed or encountered
    /// a fatal error.
    async fn run(&self);

    /// Deinitializes the platform.
    ///
    /// Called after [`run`](Self::run) returns. Releases resources and
    /// performs any cleanup required by the platform.
    fn deinit(&self);
}
