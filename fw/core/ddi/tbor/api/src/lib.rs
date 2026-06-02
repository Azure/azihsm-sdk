// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tabular Binary Object Representation (TBOR) — encoder/decoder with derive macros.
//!
//! This is the main entry point crate. It re-exports everything from
//! `azihsm_fw_ddi_tbor` (the `#![no_std]` wire format library) and optionally
//! the `#[tbor]` derive macro from `azihsm_fw_ddi_tbor_derive`.

#![no_std]

/// Re-export everything from the core wire-format library.
pub use azihsm_fw_ddi_tbor::*;
/// Re-export the `#[tbor]` derive macro when the `derive` feature is enabled.
#[cfg(feature = "derive")]
pub use azihsm_fw_ddi_tbor_derive::tbor;

// ── Protocol-level newtypes ────────────────────────────────────────────

/// Session identifier — maps to TOC entry type 0 (inline 16-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u16);

/// Convert a [`SessionId`] to its inner `u16` value.
impl From<SessionId> for u16 {
    #[inline]
    fn from(s: SessionId) -> u16 {
        s.0
    }
}

/// Create a [`SessionId`] from a raw `u16` value.
impl From<u16> for SessionId {
    #[inline]
    fn from(v: u16) -> Self {
        Self(v)
    }
}

/// Display the numeric session identifier.
impl core::fmt::Display for SessionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Key identifier — maps to TOC entry type 1 (inline 16-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId(pub u16);

/// Convert a [`KeyId`] to its inner `u16` value.
impl From<KeyId> for u16 {
    #[inline]
    fn from(k: KeyId) -> u16 {
        k.0
    }
}

/// Create a [`KeyId`] from a raw `u16` value.
impl From<u16> for KeyId {
    #[inline]
    fn from(v: u16) -> Self {
        Self(v)
    }
}

/// Display the numeric key identifier.
impl core::fmt::Display for KeyId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}
