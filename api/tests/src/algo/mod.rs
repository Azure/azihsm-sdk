// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod aes;
#[cfg(not(feature = "session-ex-tests"))]
mod ecc;
#[cfg(not(feature = "session-ex-tests"))]
mod hash;
#[cfg(not(feature = "session-ex-tests"))]
mod hmac;
#[cfg(not(feature = "session-ex-tests"))]
mod kdf;
#[cfg(not(feature = "session-ex-tests"))]
mod rsa;
// Sealing key generation is only valid on a V2 (security-domain) session,
// so include it only in the session-ex test build.
#[cfg(feature = "session-ex-tests")]
mod sealing;

use super::*;
