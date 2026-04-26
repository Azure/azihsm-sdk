// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod rng;

pub use rng::*;

pub trait HsmCrypto: HsmRng {}
