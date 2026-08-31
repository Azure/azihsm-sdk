// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! common helpers for TBOR command tests
//!

#[cfg(feature = "emu")]
/// `KeyScope::Session` discriminant.
pub(crate) const SCOPE_SESSION: u8 = 0b001;

#[cfg(feature = "emu")]
/// `KeyScope::Ephemeral` discriminant.
pub(crate) const SCOPE_EPHEMERAL: u8 = 0b010;

#[cfg(feature = "emu")]
/// `KeyScope::Local` discriminant.
pub(crate) const SCOPE_LOCAL: u8 = 0b011;

#[cfg(feature = "emu")]
/// `KeyScope::SecurityDomain` discriminant.
pub(crate) const SCOPE_SECURITY_DOMAIN: u8 = 0b100;
