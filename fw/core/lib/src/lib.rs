// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM core — application logic with platform-selected PAL.
//!
//! The concrete PAL type is selected via feature flags. The core drives
//! the IO recv/send loop using Embassy tasks with the concrete IO type.

#![cfg_attr(not(feature = "std"), no_std)]

mod ddi;
mod error;
mod hsm;
mod io;
mod op;

use azihsm_fw_hsm_core_tracing::*;
use azihsm_fw_hsm_pal_traits::*;
use embassy_sync::once_lock::OnceLock;
#[allow(unused_imports)]
pub(crate) use error::*;
pub use hsm::Hsm;
#[allow(unused_imports)]
pub(crate) use op::*;

cfg_if::cfg_if! {
    if #[cfg(feature = "pal-std")] {
        pub type Pal = azihsm_fw_hsm_pal_std::StdHsmPal;
        pub type Io = azihsm_fw_hsm_pal_std::StdHsmIo;
    } else {
        compile_error!("No PAL implementation selected. Enable a pal-* feature.");
    }
}

pub static HSM: OnceLock<Hsm> = OnceLock::new();
