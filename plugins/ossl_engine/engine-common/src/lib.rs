// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::mem::size_of;

pub mod handle_table;
use crate::handle_table::Handle;

pub const ENGINE_KEY_HANDLE_SIZE: usize = size_of::<Handle>();
