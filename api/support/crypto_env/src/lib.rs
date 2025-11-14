// Copyright (C) Microsoft Corporation. All rights reserved.

//! Crypto Environment Abstraction
//!
//! This module provides a common cryptographic environment abstraction
//! that can be shared across different HSM components like masked_key
//! and lm_key_derive.

mod crypto_env;

pub use crypto_env::*;
