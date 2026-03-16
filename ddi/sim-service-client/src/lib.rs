// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! DDI Implementation - Simulator Service Client
//!
//! Connects to the AZIHSM simulator service over a Unix Domain Socket and
//! implements the `Ddi` and `DdiDev` traits so it can be used as a drop-in
//! replacement for the in-process mock.

mod ddi;
mod dev;

pub use ddi::DdiSimService;
pub use dev::DdiSimServiceDev;
