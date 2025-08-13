// Copyright (C) Microsoft Corporation. All rights reserved.

use mcr_ddi_types::DdiGetCollateralType;

use super::*;

/// Get collateral for a virtual device
/// TODO: Collateral support for virtual device is pending
/// For now, only fetch AKCert
fn helper_get_collateral_virtual_device(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: u16,
) -> DdiResult<()> {
    let req = DdiGetCollateralCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetCollateral,
            sess_id: Some(sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetCollateralReq {
            cert_id: None,
            collateral_type: DdiGetCollateralType::AKCert,
        },
        ext: None,
    };

    let mut cookie = None;

    let resp = dev.exec_op(&req, &mut cookie);
    resp.map(|_| ())
}

/// Get collateral for a physical device
/// Logic similar to get_collateral_for_physical_device in api/ddi/lib/tests/attest_key.rs
fn helper_get_collateral_physical_device(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: u16,
) -> DdiResult<()> {
    // Gets the cert chain
    // 1. Gets the number of certs in the cert chain using DDI command GetCollateral with collateral type CertChainLen
    // 2. Gets all keys in the cert chain using DDI command GetCollateral with collateral type CertId where
    //    cert id is 0 to num_certs - 1.
    // 3. Gets the alias key cert using DDI command GetCollateral with collateral type AKCert

    let req = DdiGetCollateralCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetCollateral,
            sess_id: Some(sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetCollateralReq {
            collateral_type: DdiGetCollateralType::CertChainLen,
            cert_id: None,
        },
        ext: None,
    };
    let mut cookie = None;
    let result = dev.exec_op(&req, &mut cookie);
    let resp = result.unwrap();

    let num_certs = resp.data.num_certs.unwrap() as usize;

    for i in 0..num_certs {
        let req = DdiGetCollateralCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::GetCollateral,
                sess_id: Some(sess_id),
                rev: Some(DdiApiRev { major: 1, minor: 0 }),
            },
            data: DdiGetCollateralReq {
                collateral_type: DdiGetCollateralType::CertId,
                cert_id: Some(i as u8),
            },
            ext: None,
        };
        let mut cookie = None;
        let _resp = dev.exec_op(&req, &mut cookie);
    }

    Ok(())
}

pub(crate) fn helper_get_collateral(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
) -> DdiResult<()> {
    let resp = helper_get_device_info(dev)?;

    match resp.kind {
        DdiDeviceKind::Physical => helper_get_collateral_physical_device(dev, app_sess_id),
        DdiDeviceKind::Virtual => helper_get_collateral_virtual_device(dev, app_sess_id),
        _ => Err(DdiError::InvalidParameter),
    }
}
