// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Device-IO half of the TBOR session-establishment harness.
//!
//! The pure session crypto — ephemeral keygen, SEC1 ↔ `EccPublicKey`
//! conversion, HPKE `auth_psk` receive-export, confirm MACs, and the
//! `param_key` / `seed_envelope` derivations — lives in the reusable
//! [`azihsm_session_ex_crypto`] crate and is called directly from
//! [`init`](super::init) and [`finish`](super::finish).
//!
//! Only the step that must touch the device stays here:
//!
//! * `pk_hsm` retrieval via the TBOR cert-chain (`GetCertChainInfo`
//!   + `GetCertificate`) — the production attestation path that reads
//!     the partition-ID cert (its SubjectPublicKeyInfo carries the P-384
//!     key the FW uses as `pk_s` in HPKE `auth_psk`).

use azihsm_crypto::*;
use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_types::*;

/// Look up the partition identity public key (`pk_hsm`) via the TBOR
/// cert-chain — the production attestation path. The leaf cert is the
/// partition-ID cert; its SubjectPublicKeyInfo carries the P-384 key
/// the FW uses as `pk_s` in HPKE `auth_psk`.
///
/// Both certificate reads go over TBOR (`GetCertChainInfo` 0x1E,
/// `GetCertificate` 0x1F) rather than their MBOR equivalents, so the
/// TBOR suite establishes its own sessions using only TBOR. Reaching
/// into MBOR here made session establishment — and therefore almost
/// every test in this suite — fail on a TBOR-only firmware image with
/// `UnsupportedCmd`, even though nothing about the handshake needs the
/// other transport. Both commands are out-of-session, so they are
/// available before a session exists.
///
/// Device IO is intentionally kept here (out of the pure
/// [`azihsm_session_ex_crypto`] crate).
pub(super) fn fetch_pk_hsm(
    dev: &<AzihsmDdi as Ddi>::Dev,
) -> Result<(EccPublicKey, [u8; PK_RESP_LEN]), DdiError> {
    let info: TborGetCertChainInfoResp =
        dev.exec_op_tbor(&TborGetCertChainInfoReq::new(0), None, &mut None)?;
    let num_certs = info.num_certs;
    if num_certs == 0 {
        return Err(DdiError::InvalidParameter);
    }
    let leaf: TborGetCertResp =
        dev.exec_op_tbor(&TborGetCertReq::new(0, num_certs - 1), None, &mut None)?;
    let der = leaf.certificate.as_slice();
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
