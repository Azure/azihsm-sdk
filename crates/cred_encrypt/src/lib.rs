// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Credential and BK3 encryption for HSM operations.
//!
//! This crate provides APIs to encrypt data destined for the device over an
//! ECDH-derived secure channel. In every scheme an ephemeral ECC private key is
//! agreed with the device's ECC public key via ECDH, and the resulting shared
//! secret is expanded with HKDF-SHA-384 into the working keys. It supports two
//! schemes:
//!
//! * **Credential encryption** ([`CredentialEncryptionKey`]) — encrypts
//!   credentials (ID, PIN, Seed). The shared secret is expanded into an AES-CBC
//!   key and an HMAC key; credentials are encrypted with AES-CBC and
//!   authenticated with HMAC-SHA-384.
//! * **BK3 encryption** ([`Bk3EncryptionKey`]) — encrypts the BK3 backup key for
//!   secure provisioning. The shared secret is expanded into a transport key
//!   pair (AES-CBC + HMAC) that protects the BK3 payload, plus a separate
//!   PIN-bound HMAC key (`k_pin`) so the payload is additionally authenticated
//!   under the operator PIN and ID.

mod cred_encrypt;
mod error;

use azihsm_crypto::*;
use azihsm_ddi_mbor_codec::MborByteArray;
use azihsm_ddi_mbor_types::*;
pub use cred_encrypt::*;
pub use error::*;
