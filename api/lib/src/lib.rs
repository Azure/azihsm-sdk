// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! Azure Integrated HSM API
//!
//! This crate implements the Azure Integrated HSM API for Rust & C/C++.

mod bindings;
mod crypto;
mod ddi;
mod partition;
mod session;
mod types;

pub(crate) use azihsm_ddi::*;
use azihsm_ddi_types::*;
pub use bindings::*;
pub use partition::*;
pub use session::*;

type HsmDdi = AzihsmDdi;

lazy_static::lazy_static! {
    pub(crate) static ref DDI: HsmDdi = HsmDdi::default();
}
