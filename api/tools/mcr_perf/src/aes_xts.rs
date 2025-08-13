// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub(crate) fn helper_aes_xts_encrypt_decrypt(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    short_app_id: u8,
    key_id_1: u16,
    key_id_2: u16,
    ddi_aes_mode: DdiAesOp,
    data: Vec<u8>,
    dul: usize,
    tweak: [u8; 16usize],
) -> DdiResult<()> {
    let mcr_fp_xts_params = mcr_ddi::DdiAesXtsParams {
        key_id1: key_id_1 as u32,
        key_id2: key_id_2 as u32,
        data_unit_len: dul,
        session_id: app_sess_id,
        short_app_id,
        tweak,
    };

    let _resp = dev.exec_op_fp_xts(ddi_aes_mode, mcr_fp_xts_params, data)?;
    Ok(())
}
