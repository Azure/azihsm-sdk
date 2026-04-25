// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM platform abstraction layer trait.

use crate::HsmGdmaController;
use crate::HsmIoController;

/// The core trait that all HSM platform implementations must implement.
///
/// Defines the lifecycle of the platform: initialization, execution, and
/// deinitialization. A platform implementation provides hardware-specific
/// behavior behind this common interface.
pub trait HsmPal: HsmIoController + HsmGdmaController + Default {
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
