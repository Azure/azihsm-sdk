// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Read-only accessors for the CP alias key and certificate the HSP
//! provisions into GSRAM.
//!
//! The HSP writes the CP alias private key and its device-id-signed alias
//! certificate into fixed GSRAM locations (base `0x6100_0000`) before
//! releasing the CP cores; the layout mirrors the reference firmware's
//! `GsRamMemMap` and the SP-side `sp/src/dc_scm/mem_map/gsram_mem_map.h`.
//! The HSM reads them locally (no IPC) to serve the alias certificate in the
//! cert chain and to sign the partition-id (PID) certificate with the alias
//! key.
//!
//! Each blob is preceded by a `u32` length; the SP writes `-1`
//! (`0xFFFF_FFFF`) when the value did not fit, which we treat as "absent".

/// `alias_key_length` (u32).
const ALIAS_KEY_LEN_ADDR: usize = 0x6100_0B30;
/// `alias_key` — CP alias private key.
const ALIAS_KEY_ADDR: usize = 0x6100_0B34;
/// Maximum alias-key length (`GSRAM_MEM_MAP_ALIAS_KEY_SIZE`).
const ALIAS_KEY_MAX: usize = 0x40;

/// `alias_cert_length` (u32).
const ALIAS_CERT_LEN_ADDR: usize = 0x6100_0B74;
/// `alias_cert` — alias certificate (DER) signed by the device id.
const ALIAS_CERT_ADDR: usize = 0x6100_0B78;
/// Maximum alias-cert length (`GSRAM_MEM_MAP_ALIAS_CERT_SIZE`).
const ALIAS_CERT_MAX: usize = 0x488;

/// Read a length prefix, mapping the SP "too long" sentinel (`u32::MAX`) and
/// any out-of-range length (larger than the field's storage capacity) to 0
/// (absent). A length past capacity would otherwise yield truncated, non-empty
/// data, so it is treated as unprovisioned rather than silently clamped.
#[inline]
fn read_len(len_addr: usize, max: usize) -> usize {
    // SAFETY: `len_addr` is a fixed, 4-byte-aligned GSRAM address the HSP
    // populated before the CP cores were released; the read is within the
    // reserved SP-shared block.
    let len = unsafe { core::ptr::read_volatile(len_addr as *const u32) } as usize;
    if len > max { 0 } else { len }
}

/// The alias certificate DER bytes, or an empty slice if the SP did not
/// provision one.
pub(crate) fn alias_cert() -> &'static [u8] {
    let len = read_len(ALIAS_CERT_LEN_ADDR, ALIAS_CERT_MAX);
    // SAFETY: `ALIAS_CERT_ADDR .. +len` lies within the `alias_cert` field
    // (capped at `ALIAS_CERT_MAX`); the region is 'static GSRAM.
    unsafe { core::slice::from_raw_parts(ALIAS_CERT_ADDR as *const u8, len) }
}

/// The alias private key bytes, or an empty slice if the SP did not
/// provision one.
pub(crate) fn alias_key() -> &'static [u8] {
    let len = read_len(ALIAS_KEY_LEN_ADDR, ALIAS_KEY_MAX);
    // SAFETY: `ALIAS_KEY_ADDR .. +len` lies within the `alias_key` field
    // (capped at `ALIAS_KEY_MAX`); the region is 'static GSRAM.
    unsafe { core::slice::from_raw_parts(ALIAS_KEY_ADDR as *const u8, len) }
}
