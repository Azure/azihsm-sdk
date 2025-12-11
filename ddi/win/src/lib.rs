// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! DDI Implementation - MCR Windows Device

#![cfg(target_os = "windows")]

mod ddi;
mod dev;
mod io_event;

pub use ddi::DdiWin;
pub use dev::DdiWinDev;
