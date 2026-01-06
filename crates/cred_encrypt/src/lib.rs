// Copyright (C) Microsoft Corporation. All rights reserved.

//! Credential Encryption for HSM operations.
//!
//! This crate provides APIs to allow encryption of credentials (ID, PIN, Seed).
//! The encryption is based on ECDH key agreement using an ECC public key from the device
//! and an ephemeral ECC private key generated for instance. The derived shared secret
//! is then used to derive AES and HMAC keys using HKDF. The AES key is used to encrypt
//! the credentials using AES-CBC, and the HMAC key is used to sign the encrypted
//! credentials to ensure integrity.

mod cred_encrypt;
mod error;

use azihsm_crypto::*;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::*;
pub use cred_encrypt::*;
pub use error::*;
