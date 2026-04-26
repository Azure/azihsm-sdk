// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod rng;

pub use rng::*;

use super::*;

pub trait HsmCrypto: HsmRng {}
