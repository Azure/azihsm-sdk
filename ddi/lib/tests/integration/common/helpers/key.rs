// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

pub fn rsa_secure_import_key(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key: &[u8],
    key_class: DdiKeyClass,
    key_usage: DdiKeyUsage,
    key_tag: Option<u16>,
) -> Result<DdiRsaUnwrapCmdResp, DdiError> {
    let session_id = session_id.expect("session id required");

    let (unwrap_key_id, unwrap_pub_key_der, _) = get_unwrapping_key(dev, session_id);

    let wrapped_key = wrap_data(unwrap_pub_key_der, key);

    let mut der = [0u8; 3072];
    der[..wrapped_key.len()].copy_from_slice(&wrapped_key);
    let der_len = wrapped_key.len();

    let resp = helper_rsa_unwrap(
        dev,
        Some(session_id),
        rev,
        unwrap_key_id,
        MborByteArray::new(der, der_len).expect("failed to create byte array"),
        key_class,
        DdiRsaCryptoPadding::Oaep,
        DdiHashAlgorithm::Sha256,
        key_tag,
        helper_key_properties(key_usage, DdiKeyAvailability::App),
    )?;

    Ok(resp)
}
