// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ECC-P384 key-attestation report builder for AZIHSM firmware.
//!
//! Emits CBOR / `COSE_Sign1` reports byte-identical to mcr-hsm and
//! the AZIHSM simulator, without taking a `minicbor` dependency in
//! firmware.  Variable bytes are patched into pre-baked templates
//! (see [`template`]) and the SHA-384 + ECDSA-P384 signing step is
//! routed through the supplied [`HsmCrypto`](azihsm_fw_hsm_pal_traits::HsmCrypto)
//! implementation.
//!
//! See [`key_report`] for the single public entry point.

#![no_std]

mod builder;
#[allow(dead_code)]
mod template;

pub use builder::*;
