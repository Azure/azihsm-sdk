// Copyright (C) Microsoft Corporation. All rights reserved.

//! Generic secret key types.
//!
//! This module provides a generic secret key wrapper that represents key material stored in the
//! HSM but not tied to a specific algorithm type at the N-API layer.
//!
//! The primary use case is derived secrets (for example, an ECDH shared secret). The returned
//! value is still an HSM-managed key handle with associated properties; callers should set
//! appropriate usage flags and lifetimes via `HsmKeyProps` when creating/deriving the secret.

// Re-export shared algo/key types from the parent module.
pub use super::*;

// A generic secret key stored in the HSM.
//
// This type typically represents the output of key-derivation operations that yield raw secret
// material (e.g., ECDH). It intentionally does not encode an algorithm-specific key kind.
define_hsm_key!(pub HsmGenericSecretKey);

impl HsmDerivationKey for HsmGenericSecretKey {}
