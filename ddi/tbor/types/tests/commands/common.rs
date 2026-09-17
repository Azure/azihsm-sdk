// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_ddi_tbor_types::PSK_LEN;

//Common constants and helpers for TBOR command tests.

/// `KeyScope::Session` discriminant.
pub(crate) const SCOPE_SESSION: u8 = 0b001;

/// `KeyScope::Ephemeral` discriminant.
pub(crate) const SCOPE_EPHEMERAL: u8 = 0b010;

/// `KeyScope::Local` discriminant.
pub(crate) const SCOPE_LOCAL: u8 = 0b011;

/// `KeyScope::SecurityDomain` discriminant.
pub(crate) const SCOPE_SECURITY_DOMAIN: u8 = 0b100;

/// `SessionType` role identifier for Crypto-Officer sessions.
pub(crate) const CO: u8 = 0;

/// `SessionType` role identifier for Crypto-User sessions.
pub(crate) const CU: u8 = 1;

pub(crate) const ROTATED_CU_PSK: [u8; PSK_LEN] = [0xA5; PSK_LEN];
