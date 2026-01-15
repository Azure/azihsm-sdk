// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_napi::*;

use super::*;
use crate::AzihsmError;
use crate::AzihsmHandle;
use crate::HANDLE_TABLE;
use crate::handle_table::HandleType;

impl TryFrom<&AzihsmAlgo> for HsmRsaKeyUnwrappingKeyGenAlgo {
    type Error = AzihsmError;

    /// Converts a C FFI algorithm specification to HsmRsaKeyUnwrappingKeyGenAlgo.
    fn try_from(_algo: &AzihsmAlgo) -> Result<Self, Self::Error> {
        Ok(HsmRsaKeyUnwrappingKeyGenAlgo::default())
    }
}

/// Generate an RSA key pair and return handles
pub(crate) fn rsa_generate_key_pair(
    session: &HsmSession,
    algo: &AzihsmAlgo,
    priv_key_props: HsmKeyProps,
    pub_key_props: HsmKeyProps,
) -> Result<(AzihsmHandle, AzihsmHandle), AzihsmError> {
    let mut rsa_algo = HsmRsaKeyUnwrappingKeyGenAlgo::try_from(algo)?;
    let (priv_key, pub_key) =
        HsmKeyManager::generate_key_pair(session, &mut rsa_algo, priv_key_props, pub_key_props)?;

    let priv_handle = HANDLE_TABLE.alloc_handle(HandleType::RsaPrivKey, Box::new(priv_key));
    let pub_handle = HANDLE_TABLE.alloc_handle(HandleType::RsaPubKey, Box::new(pub_key));

    Ok((priv_handle, pub_handle))
}
