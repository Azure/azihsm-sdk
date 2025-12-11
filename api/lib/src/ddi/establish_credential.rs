// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn get_establish_cred_encryption_key(
    dev: &<HsmDdi as Ddi>::Dev,
    rev: DdiApiRev,
) -> Result<DdiGetEstablishCredEncryptionKeyCmdResp, DdiError> {
    let req = DdiGetEstablishCredEncryptionKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetEstablishCredEncryptionKey,
            sess_id: None,
            rev: Some(rev),
        },
        data: DdiGetEstablishCredEncryptionKeyReq {},
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn establish_credential(
    dev: &<HsmDdi as Ddi>::Dev,
    rev: DdiApiRev,
    encrypted_credential: DdiEncryptedEstablishCredential,
    pub_key: DdiDerPublicKey,
    masked_bk3: MborByteArray<1024>,
    bmk: MborByteArray<1024>,
    masked_unwrapping_key: MborByteArray<1024>,
) -> Result<DdiEstablishCredentialCmdResp, DdiError> {
    let req = DdiEstablishCredentialCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::EstablishCredential,
            sess_id: None,
            rev: Some(rev),
        },
        data: DdiEstablishCredentialReq {
            encrypted_credential,
            pub_key,
            masked_bk3,
            bmk,
            masked_unwrapping_key,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
