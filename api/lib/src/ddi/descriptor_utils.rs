// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Out-of-band SGL descriptor packing shared by TBOR commands that ship
//! DER certificate chains / reports out of band (`PartFinal`, the SD
//! backup family).
//!
//! Each item ships as its own OOB SGL Data Block; the firmware locates it
//! by the descriptor's `index` (its position in the shared `oob` item
//! list) and reads `length` bytes from it.

use azihsm_ddi_tbor_types::*;

use super::*;

/// Appends a certificate chain's DER bytes to `oob`, returning the
/// matching `(index, length)` descriptors. Rejects an empty chain, a
/// chain longer than `max_certs`, an empty (zero-length) cert, or a cert
/// whose length overflows the 16-bit descriptor field.
pub(crate) fn push_cert_chain<'a>(
    chain: &'a [HsmCert<'a>],
    oob: &mut Vec<&'a [u8]>,
    max_certs: usize,
) -> HsmResult<Vec<CertDescriptor>> {
    // Firmware evidence verification rejects an empty chain as InvalidArg;
    // fail fast rather than round-trip a guaranteed rejection.
    if chain.is_empty() || chain.len() > max_certs {
        return Err(HsmError::InvalidArgument);
    }
    let mut descriptors = Vec::with_capacity(chain.len());
    for cert in chain {
        let der = cert.cert;
        if der.is_empty() || der.len() > u16::MAX as usize {
            return Err(HsmError::InvalidArgument);
        }
        // Descriptor index = position in the shared OOB list (must fit u8).
        let index = u8::try_from(oob.len()).map_err(|_| HsmError::InvalidArgument)?;
        descriptors.push(CertDescriptor {
            index,
            length: tbor_int::U16::new(der.len() as u16),
        });
        oob.push(der);
    }
    Ok(descriptors)
}

/// Appends a COSE_Sign1 report DER to `oob`, returning its descriptor.
/// Rejects an empty report (firmware verification rejects `report_len ==
/// 0` as InvalidArg) or one exceeding the 16-bit length.
pub(crate) fn push_report<'a>(
    report: &'a [u8],
    oob: &mut Vec<&'a [u8]>,
) -> HsmResult<ReportDescriptor> {
    if report.is_empty() || report.len() > u16::MAX as usize {
        return Err(HsmError::InvalidArgument);
    }
    let index = u8::try_from(oob.len()).map_err(|_| HsmError::InvalidArgument)?;
    let descriptor = ReportDescriptor {
        index,
        length: tbor_int::U16::new(report.len() as u16),
    };
    oob.push(report);
    Ok(descriptor)
}
