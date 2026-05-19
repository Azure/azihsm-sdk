// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HPKE error types.
//!
//! Currently a placeholder — HPKE operations surface
//! [`azihsm_fw_hsm_pal_traits::HsmError`] directly via [`HsmResult`]
//! returns, since every error in the crate is forwarded from the
//! underlying PAL traits ([`HsmEcc`], [`HsmCrypto`], [`HsmKdf`],
//! [`HsmHmac`], [`HsmRng`]) without any HPKE-specific failure modes.
//!
//! A dedicated `HpkeError` enum will be introduced if/when the crate
//! gains failure modes that cannot be expressed as PAL errors (for
//! example RFC 9180 single-shot input length checks that should be
//! distinct from generic [`HsmError::InvalidArg`]).
//!
//! [`HsmError`]: azihsm_fw_hsm_pal_traits::HsmError
//! [`HsmError::InvalidArg`]: azihsm_fw_hsm_pal_traits::HsmError::InvalidArg
//! [`HsmResult`]: azihsm_fw_hsm_pal_traits::HsmResult
//! [`HsmEcc`]: azihsm_fw_hsm_pal_traits::HsmEcc
//! [`HsmCrypto`]: azihsm_fw_hsm_pal_traits::HsmCrypto
//! [`HsmKdf`]: azihsm_fw_hsm_pal_traits::HsmKdf
//! [`HsmHmac`]: azihsm_fw_hsm_pal_traits::HsmHmac
//! [`HsmRng`]: azihsm_fw_hsm_pal_traits::HsmRng
