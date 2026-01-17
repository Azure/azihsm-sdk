// Copyright (C) Microsoft Corporation. All rights reserved.

//! Secret key algorithms and types.
//!
//! This module defines generic "secret" key types used to represent derived or imported
//! key material that does not map to a more specific asymmetric/symmetric key type.
//! A common producer is an ECDH operation, where the output is a shared secret.

mod key;

pub use key::*;

use super::*;
