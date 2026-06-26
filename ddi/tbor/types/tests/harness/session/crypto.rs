// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Device-IO + error-mapping shim for the TBOR session harness.
//!
//! The handshake math lives in the standalone [`azihsm_session_ex_crypto`]
//! crate — the single host-side source of truth shared with
//! `azihsm_api`. The [`init`](super::init) and [`finish`](super::finish)
//! harness code calls that crate directly, mapping its
//! backend-agnostic `SessionExCryptoError` onto [`DdiError`] inline at
//! each call site (the orphan rule prevents a blanket `From` impl).
//!
//! Only the device-IO `pk_hsm` retrieval stays here: it walks the MBOR
//! cert-chain (`GetCertChainInfo` + `GetCertificate`), which is
//! harness-specific and not part of the pure crypto crate.

use azihsm_crypto::EccPublicKey;
use azihsm_crypto::ImportableKey;
use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_mbor_test_helpers::helper_get_cert_chain_info;
use azihsm_ddi_mbor_test_helpers::helper_get_certificate;
use azihsm_ddi_tbor_types::PK_RESP_LEN;

/// Look up the partition identity public key (`pk_hsm`) via the MBOR
/// cert-chain — the production attestation path. The leaf cert is the
/// partition-ID cert; its SubjectPublicKeyInfo carries the P-384 key
/// the FW uses as `pk_s` in HPKE `auth_psk`.
///
/// Device IO is intentionally kept here (out of the pure
/// [`azihsm_session_ex_crypto`] crate).
pub(super) fn fetch_pk_hsm(
    dev: &<AzihsmDdi as Ddi>::Dev,
) -> Result<(EccPublicKey, [u8; PK_RESP_LEN]), DdiError> {
    let info = helper_get_cert_chain_info(dev)?;
    let num_certs = info.data.num_certs;
    if num_certs == 0 {
        return Err(DdiError::InvalidParameter);
    }
    let leaf = helper_get_certificate(dev, num_certs - 1)?;
    let der = leaf.data.certificate.as_slice();
    let pk_der = extract_subject_public_key_der(der)?;
    let pk = EccPublicKey::from_bytes(&pk_der).map_err(|_| DdiError::InvalidParameter)?;
    let sec1 =
        azihsm_session_ex_crypto::ec_pub_to_sec1(&pk).map_err(|_| DdiError::InvalidParameter)?;
    Ok((pk, sec1))
}

/// Pull the DER-encoded SubjectPublicKeyInfo out of an X.509
/// certificate. Uses [`x509::X509Certificate`] — the same parser the
/// MBOR test harness uses for the same purpose.
fn extract_subject_public_key_der(cert_der: &[u8]) -> Result<Vec<u8>, DdiError> {
    use x509::X509Certificate;
    use x509::X509CertificateOp;

    let cert = X509Certificate::from_der(cert_der).map_err(|_| DdiError::InvalidParameter)?;
    cert.get_public_key_der()
        .map_err(|_| DdiError::InvalidParameter)
}
