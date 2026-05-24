// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use thiserror::Error;

use super::*;

pub fn helper_get_sealed_bk3(
    dev: &<AzihsmDdi as Ddi>::Dev,
) -> Result<DdiGetSealedBk3CmdResp, DdiError> {
    let req = DdiGetSealedBk3CmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetSealedBk3,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetSealedBk3Req {},
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

/// Error returned by [`helper_get_mobk_from_tpm`].
///
/// Carries a stage-tagged message so `.expect(...)` panic output stays
/// useful for either failure mode (DDI fetch or TPM unseal).
#[derive(Debug, Error)]
#[error("get_mobk_from_tpm failed: {0}")]
pub(crate) struct MobkFromTpmError(pub String);

/// Fetches the sealed BK3 from the device and unseals it via the TPM,
/// returning the masked owner backup key (MOBK).
pub(crate) fn helper_get_mobk_from_tpm(
    dev: &<AzihsmDdi as Ddi>::Dev,
) -> Result<Vec<u8>, MobkFromTpmError> {
    let resp = helper_get_sealed_bk3(dev)
        .map_err(|e| MobkFromTpmError(format!("GetSealedBk3 DDI: {e:?}")))?;
    unseal_tpm_backup_key(resp.data.sealed_bk3.as_slice())
        .map_err(|e| MobkFromTpmError(format!("{e}")))
}
