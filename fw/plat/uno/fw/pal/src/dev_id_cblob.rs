// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Read-only accessor for the device-id certificate CBLOB the HSP packs into
//! CP1/HSM DTCM at boot.
//!
//! The SP/HSP writes the device-id certificate chain (root + intermediates +
//! device-id) plus the chain thumbprint into the fixed `DEV_ID_CERT_BLOB` DTCM
//! region before releasing the CP cores, so the HSM serves GetCertChainInfo /
//! GetCertificate locally with no IPC. The [`cert_blob`](azihsm_fw_uno_cert_blob)
//! crate parses and bounds-checks the container.

use azihsm_fw_uno_cert_blob::CertBlob;
use azihsm_fw_uno_reg_soc::hsm_dtcm;

/// Base address of the device-id CBLOB region in DTCM.
const REGION_BASE: usize = (hsm_dtcm::HSM_DTCM_BASE + hsm_dtcm::DEV_ID_CERT_BLOB_OFFSET) as usize;
/// Size of the device-id CBLOB region (bytes).
const REGION_SIZE: usize = hsm_dtcm::DEV_ID_CERT_BLOB_SIZE as usize;

/// Parse the boot-time device-id certificate CBLOB from DTCM.
///
/// Returns `None` if the HSP did not populate a structurally valid blob (e.g.
/// on bring-up firmware where the HSP handshake is not yet implemented).
pub(crate) fn dev_id_cert_blob() -> Option<CertBlob<'static>> {
    // SAFETY: `DEV_ID_CERT_BLOB` is a fixed, 'static DTCM region the HSP
    // populated before the CP cores were released; `CertBlob::parse`
    // bounds-checks the entire container structure internally.
    let region = unsafe { core::slice::from_raw_parts(REGION_BASE as *const u8, REGION_SIZE) };
    CertBlob::parse(region)
}
