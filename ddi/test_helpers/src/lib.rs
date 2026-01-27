// Copyright (C) Microsoft Corporation. All rights reserved.

#![allow(clippy::unwrap_used)]

mod aes;
mod api_rev;
mod attest_key;
mod change_pin;
mod credential;
mod device;
mod ecc;
mod ecdh;
mod error;
mod func;
mod get_cert;
mod get_sealed_bk3;
mod hkdf;
mod hmac;
mod init_bk3;
mod kbkdf;
mod key;
mod key_properties;
mod mask;
mod report;
mod rsa;
mod session;
mod set_sealed_bk3;

pub use aes::*;
pub use api_rev::*;
pub use attest_key::*;
use azihsm_ddi::*;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::*;
pub use change_pin::*;
pub use credential::*;
pub use device::*;
pub use ecc::*;
pub use ecdh::*;
pub use error::*;
pub use func::*;
pub use get_cert::*;
pub use get_sealed_bk3::*;
pub use hkdf::*;
pub use hmac::*;
pub use init_bk3::*;
pub use kbkdf::*;
pub use key::*;
pub use key_properties::*;
pub use mask::*;
pub use report::*;
pub use rsa::*;
pub use session::*;
pub use set_sealed_bk3::*;
