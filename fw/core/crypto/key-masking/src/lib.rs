// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
#![forbid(unsafe_code)]

//! Masked-key envelopes: wrap a target key into a self-contained,
//! authenticated blob under a caller-supplied masking key.
//!
//! Two on-wire formats live in this crate, behind separate submodules
//! so callers pick the right one explicitly:
//!
//! * [`cbc`] — **v1**, AES-CBC-256 + HMAC-SHA-384 (encrypt-then-MAC).
//!   Host-visible wire format used by `init_bk3`,
//!   `establish_credential`, live migration, and the host-side
//!   simulator.  MBOR-encoded [`DdiMaskedKeyMetadata`](
//!   azihsm_fw_ddi_mbor_types::masked_key::DdiMaskedKeyMetadata)
//!   embedded inside the blob.  Pinned by the cross-domain
//!   `MaskedKey` contract.
//!
//! * [`aead`] — **v2**, AEAD envelope (today AES-256-GCM) layered on
//!   [`azihsm_fw_core_crypto_aead_envelope`].  Firmware-internal
//!   format used for session BMK wrapping; carries vault primitives
//!   ([`HsmVaultKeyKind`](azihsm_fw_hsm_pal_traits::HsmVaultKeyKind),
//!   [`HsmVaultKeyAttrs`](azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs))
//!   in a fixed 96 B AAD record.
//!
//! The two formats are not byte-compatible and serve different
//! audiences: v1 for cross-domain blobs that the host SDK must
//! parse, v2 for firmware-internal wrapping where the schema can be
//! tighter and the algorithm can evolve without touching host code.

pub mod aead;
pub mod cbc;
