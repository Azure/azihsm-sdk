// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end `PartFinal` coverage.
//!
//! Emulator builds exercise full certificate-chain validation, while the
//! no-feature Linux build exercises the native driver path on real hardware.

#[cfg(feature = "emu")]
mod emu;

#[cfg(all(
    target_os = "linux",
    not(any(feature = "emu", feature = "mock", feature = "sock"))
))]
mod hw;
