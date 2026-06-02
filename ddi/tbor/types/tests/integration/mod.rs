// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration test modules. Each per-command file is gated on the
//! backend feature(s) that can satisfy it (e.g., TBOR commands require
//! `emu` for a real round-trip).

pub mod get_api_rev;
