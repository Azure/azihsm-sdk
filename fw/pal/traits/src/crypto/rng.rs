// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

pub trait HsmRng {
    /// Fill the provided buffer with cryptographically secure random bytes.
    fn rng_fill_bytes(&mut self, buf: &mut [u8]) -> HsmResult<()>;
}
