// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_napi::*;

use crate::AzihsmError;

use super::*;

impl TryFrom<&AzihsmAlgo> for HsmEccKeyGenAlgo {
    type Error = AzihsmError;

    /// Converts a C FFI algorithm specification to HsmEccKeyGenAlgo.
    fn try_from(_algo: &AzihsmAlgo) -> Result<Self, Self::Error> {
        Ok(HsmEccKeyGenAlgo::default())
    }
}
