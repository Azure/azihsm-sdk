// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::unwrap_used)]

//! Tests for Elliptic Curve Cryptography (ECC) operations.
mod ecc_from_okm_a2_1;
mod ecc_from_scalar;
mod ecc_helpers;
mod ecc_hsm_format;
mod ecc_p256;
mod ecc_p384;
mod ecc_p521;
mod ecdh_p256;
mod ecdh_p384;
mod ecdh_p521;
mod ecdsa_p256;
mod ecdsa_p384;
mod ecdsa_p521;

pub(crate) use ecc_helpers::*;

use super::*;
