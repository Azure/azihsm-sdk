// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub(crate) fn helper_aes_gcm_encrypt_decrypt(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    short_app_id: u8,
    key_id: u16,
    ddi_aes_mode: DdiAesOp,
    data: Vec<u8>,
    iv: [u8; 12usize],
    aad: Option<Vec<u8>>,
    tag: Option<[u8; 16usize]>,
) -> DdiResult<(Vec<u8>, Option<[u8; 16usize]>)> {
    let mcr_fp_gcm_params = mcr_ddi::DdiAesGcmParams {
        iv,
        aad,
        key_id: key_id as u32,
        tag,
        session_id: app_sess_id,
        short_app_id,
    };
    let resp = dev.exec_op_fp_gcm(ddi_aes_mode, mcr_fp_gcm_params, data)?;
    Ok((resp.data, resp.tag))
}
