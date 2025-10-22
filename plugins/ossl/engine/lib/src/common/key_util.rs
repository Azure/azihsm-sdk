// Copyright (C) Microsoft Corporation. All rights reserved.
use mcr_api_resilient::ManticoreCertificate;

#[macro_export]
macro_rules! get_or_create_keydata {
    ($ctx:expr, $keydata_type:ty) => {{
        if let Some(keydata) = $ctx.get_data() {
            Ok(keydata)
        } else {
            let keydata = <$keydata_type>::new();
            $ctx.set_data(keydata);
            $ctx.get_data().ok_or(OpenSSLError::InvalidKeyData)
        }
    }};
}

/// Encode attestation report and certificate into a single binary buffer.
/// Output buffer format (all numbers are little-endian):
/// - Header
/// - 4 bytes: version, currently 1
/// - 4 bytes: buffer total length, including header
/// - metadata
/// - 4 bytes: length of attestation report in bytes
/// - 4 bytes: length of certificate in bytes
/// - payload
/// - N bytes: attestation report
/// - M bytes: certificate
pub fn encode_attestation_payload(report: &[u8], cert: &ManticoreCertificate) -> Vec<u8> {
    // Header version, only 1 is supported for now
    const VERSION: u32 = 1;

    // Extract certificate chain based on certificate type
    let cert_chain = match cert {
        ManticoreCertificate::PhysicalManticore(cert_chain) => cert_chain,
        ManticoreCertificate::VirtualManticore {
            ak_cert,
            tee_cert_chain: _,
            tee_report: _,
        } => ak_cert,
    };

    let len_report = report.len() as u32;
    let len_cert_chain = cert_chain.len() as u32;

    // Calculate total buffer length including header
    let len_buffer = 4 + // version
                      4 + // total length
                      4 + // report length
                      4 + // cert length
                      len_report + // report data
                      len_cert_chain; // cert data

    let mut buffer = Vec::with_capacity(len_buffer as usize);

    // Header: version (4 bytes)
    buffer.extend_from_slice(&VERSION.to_le_bytes());

    // Header: buffer total length (4 bytes)
    buffer.extend_from_slice(&len_buffer.to_le_bytes());

    // Metadata: length of attestation report (4 bytes)
    buffer.extend_from_slice(&len_report.to_le_bytes());

    // Metadata: length of certificate (4 bytes)
    buffer.extend_from_slice(&len_cert_chain.to_le_bytes());

    // Payload: attestation report
    buffer.extend_from_slice(report);

    // Payload: certificate
    buffer.extend_from_slice(cert_chain);

    buffer
}
