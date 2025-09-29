// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

/// Get certificate for a virtual device
/// TODO: Collateral/certificate support for virtual device is pending
/// For now, only fetch AKCert
fn helper_get_certificate_virtual_device(dev: &<DdiTest as Ddi>::Dev) -> DdiResult<()> {
    let req = DdiGetCertChainInfoCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetCertChainInfo,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetCertChainInfoReq { slot_id: 0 },
        ext: None,
    };
    let mut cookie = None;
    let result = dev.exec_op(&req, &mut cookie);
    let resp = result.unwrap();

    let num_certs = resp.data.num_certs;

    for i in 0..num_certs {
        let req = DdiGetCertificateCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::GetCertificate,
                sess_id: None,
                rev: Some(DdiApiRev { major: 1, minor: 0 }),
            },
            data: DdiGetCertificateReq {
                slot_id: 0,
                cert_id: i,
            },
            ext: None,
        };
        let mut cookie = None;
        let _resp = dev.exec_op(&req, &mut cookie);
    }

    Ok(())
}

/// Get certificate for a physical device
/// Logic similar to get_certificate_for_physical_device in api/ddi/lib/tests/attest_key.rs
fn helper_get_certificate_physical_device(dev: &<DdiTest as Ddi>::Dev) -> DdiResult<()> {
    // Gets the cert chain
    // 1. Gets the number of certs in the cert chain using DDI command GetCertChainInfo on slot 0.
    // 2. Gets all keys in the cert chain using DDI command GetCertificate with CertId where
    //    cert id is 0 to num_certs - 1.
    let req = DdiGetCertChainInfoCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetCertChainInfo,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetCertChainInfoReq { slot_id: 0 },
        ext: None,
    };
    let mut cookie = None;
    let result = dev.exec_op(&req, &mut cookie);
    let resp = result.unwrap();

    let num_certs = resp.data.num_certs;

    for i in 0..num_certs {
        let req = DdiGetCertificateCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::GetCertificate,
                sess_id: None,
                rev: Some(DdiApiRev { major: 1, minor: 0 }),
            },
            data: DdiGetCertificateReq {
                slot_id: 0,
                cert_id: i,
            },
            ext: None,
        };
        let mut cookie = None;
        let _resp = dev.exec_op(&req, &mut cookie);
    }

    Ok(())
}

pub(crate) fn helper_get_certificate(dev: &<DdiTest as Ddi>::Dev) -> DdiResult<()> {
    let resp = helper_get_device_info(dev)?;

    match resp.kind {
        DdiDeviceKind::Physical => helper_get_certificate_physical_device(dev),
        DdiDeviceKind::Virtual => helper_get_certificate_virtual_device(dev),
        _ => Err(DdiError::InvalidParameter),
    }
}
