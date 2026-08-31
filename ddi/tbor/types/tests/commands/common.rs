// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! common helpers for TBOR command tests
//!

/// `KeyScope::Session` discriminant.
pub(crate) const SCOPE_SESSION: u8 = 0b001;

/// `KeyScope::Ephemeral` discriminant.
pub(crate) const SCOPE_EPHEMERAL: u8 = 0b010;

/// `KeyScope::Local` discriminant.
pub(crate) const SCOPE_LOCAL: u8 = 0b011;

/// `KeyScope::SecurityDomain` discriminant.
pub(crate) const SCOPE_SECURITY_DOMAIN: u8 = 0b100;
