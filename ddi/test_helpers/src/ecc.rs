// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn helper_ecc_generate_key_pair(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    curve: DdiEccCurve,
    key_tag: Option<u16>,
    key_properties: DdiKeyProperties,
) -> Result<DdiEccGenerateKeyPairCmdResp, DdiError> {
    let req = DdiEccGenerateKeyPairCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::EccGenerateKeyPair,
            sess_id,
            rev,
        },
        data: DdiEccGenerateKeyPairReq {
            curve,
            key_tag,
            key_properties: key_properties
                .try_into()
                .map_err(|_| DdiError::InvalidParameter)?,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

// Max size of a ECC Public Key
pub const DER_MAX_SIZE: usize = 192;

pub fn helper_create_ecc_key_pairs(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    curve: DdiEccCurve,
    key_tag: Option<u16>,
) -> (
    u16,
    [u8; DER_MAX_SIZE],
    usize,
    u16,
    [u8; DER_MAX_SIZE],
    usize,
) {
    // Initalize first keypair

    let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

    let resp = helper_ecc_generate_key_pair(dev, sess_id, rev, curve, key_tag, key_props);

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();

    let priv_key_id1 = resp.data.private_key_id;
    let pub_key1 = resp.data.pub_key.unwrap();
    let mut der1 = [0u8; DER_MAX_SIZE];
    let der1_len = pub_key1.der.len();
    der1[..der1_len].clone_from_slice(&pub_key1.der.data()[..der1_len]);

    // Initialize second key pair

    let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

    let resp = helper_ecc_generate_key_pair(dev, sess_id, rev, curve, key_tag, key_props);

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();

    let priv_key_id2 = resp.data.private_key_id;
    let pub_key2: DdiDerPublicKey = resp.data.pub_key.unwrap();
    let mut der2 = [0u8; DER_MAX_SIZE];
    let der2_len = pub_key2.der.len();
    der2[..der2_len].clone_from_slice(&pub_key2.der.data()[..der2_len]);

    (priv_key_id1, der1, der1_len, priv_key_id2, der2, der2_len)
}

pub fn helper_ecc_sign(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_id: u16,
    digest: MborByteArray<96>,
    digest_algo: DdiHashAlgorithm,
) -> Result<DdiEccSignCmdResp, DdiError> {
    let req = DdiEccSignCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::EccSign,
            sess_id,
            rev,
        },
        data: DdiEccSignReq {
            key_id,
            digest,
            digest_algo,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
