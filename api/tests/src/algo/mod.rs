// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod aes;
mod ecc;
mod hash;
mod hmac;
mod kdf;
mod rsa;
// Sealing key generation is only valid on a V2 (security-domain) session,
// which a real backend (emu or hardware) provides; gate the module out only
// for the mock backend.
#[cfg(not(feature = "mock"))]
mod sealing;

use super::*;
