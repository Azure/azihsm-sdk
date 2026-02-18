// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone, Copy)]
pub enum CredEncErr {
    #[error("ecc key import error")]
    EccKeyImportError,
    #[error("ecc key generation error")]
    EccKeyGenError,
    #[error("ecc key export error")]
    EccKeyExportError,
    #[error("slice too big")]
    SliceTooBig,
    #[error("ecdh derive error")]
    EcdhDeriveError,
    #[error("hkdf derive error")]
    HkdfDeriveError,
    #[error("secret export error")]
    SecretExportError,
    #[error("aes key import error")]
    AesKeyImportError,
    #[error("aes cbc encrypt error")]
    AesCbcEncryptError,
    #[error("hmac key import error")]
    HmacKeyImportError,
    #[error("hmac sign error")]
    HmacSignError,
    #[error("rng error")]
    RngError,
}
