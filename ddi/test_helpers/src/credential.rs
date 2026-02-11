// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

pub fn helper_establish_credential(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    encrypted_credential: DdiEncryptedEstablishCredential,
    pub_key: DdiDerPublicKey,
    masked_bk3: MborByteArray<1024>,
    bmk: MborByteArray<1024>,
    masked_unwrapping_key: MborByteArray<1024>,
    signed_pid: MborByteArray<1024>,
    pota_pub_key: DdiDerPublicKey,
) -> Result<DdiEstablishCredentialCmdResp, DdiError> {
    let req = DdiEstablishCredentialCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::EstablishCredential,
            sess_id,
            rev,
        },
        data: DdiEstablishCredentialReq {
            encrypted_credential,
            pub_key,
            masked_bk3,
            bmk,
            masked_unwrapping_key,
            pota_sig: signed_pid,
            pota_pub_key,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
