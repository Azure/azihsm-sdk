// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for X509 certificate and CSR templates.
//!
//! Uses azihsm_crypto for key generation, signing, and hashing.
//! Uses x509 crate for certificate parsing and chain validation.
//! OpenSSL-specific structural tests are gated behind `#[cfg(target_os = "linux")]`.

#![allow(clippy::unwrap_used)]

use azihsm_crypto::EccCurve;
use azihsm_crypto::EccKeyOp;
use azihsm_crypto::EccPrivateKey;
use azihsm_crypto::EcdsaAlgo;
use azihsm_crypto::HashAlgo;
use azihsm_crypto::HashOp;
use azihsm_crypto::SignOp;
use azihsm_fw_hsm_std_x509::cert_builder::IntermediateCertParams;
use azihsm_fw_hsm_std_x509::cert_builder::KeyUsage;
use azihsm_fw_hsm_std_x509::cert_builder::LeafCertParams;
use azihsm_fw_hsm_std_x509::cert_builder::RootCertParams;
use azihsm_fw_hsm_std_x509::cert_builder::CN_LEN;
use azihsm_fw_hsm_std_x509::cert_builder::SN_LEN;
use azihsm_fw_hsm_std_x509::cert_builder::{self};
#[cfg(target_os = "linux")]
use azihsm_fw_hsm_std_x509::csr_builder::DeviceCsrParams;
#[cfg(target_os = "linux")]
use azihsm_fw_hsm_std_x509::csr_builder::{self};
use x509::X509Certificate;
use x509::X509CertificateOp;

/// Test key pair using azihsm_crypto.
struct TestKeyPair {
    private_key: EccPrivateKey,
    pubkey_bytes: [u8; 97],
}

impl TestKeyPair {
    fn generate() -> Self {
        let private_key = EccPrivateKey::from_curve(EccCurve::P384).unwrap();
        let (x, y) = private_key.coord_vec().unwrap();
        let mut pubkey_bytes = [0u8; 97];
        pubkey_bytes[0] = 0x04;
        pubkey_bytes[1..49].copy_from_slice(&x);
        pubkey_bytes[49..97].copy_from_slice(&y);
        Self {
            private_key,
            pubkey_bytes,
        }
    }

    fn sign_data(&self, data: &[u8]) -> ([u8; 48], [u8; 48]) {
        let mut algo = EcdsaAlgo::new(HashAlgo::sha384());
        // Get required size first
        let sig_len = algo.sign(&self.private_key, data, None).unwrap();
        let mut sig_buf = vec![0u8; sig_len];
        let written = algo
            .sign(&self.private_key, data, Some(&mut sig_buf))
            .unwrap();
        // azihsm_crypto returns raw r||s concatenated (96 bytes for P384)
        assert_eq!(written, 96, "ECDSA P384 raw signature should be 96 bytes");
        let mut r = [0u8; 48];
        let mut s = [0u8; 48];
        r.copy_from_slice(&sig_buf[..48]);
        s.copy_from_slice(&sig_buf[48..96]);
        (r, s)
    }

    fn compute_ski(&self) -> [u8; 20] {
        let mut algo = HashAlgo::sha1();
        let mut result = [0u8; 20];
        algo.hash(&self.pubkey_bytes, Some(&mut result)).unwrap();
        result
    }
}

fn test_serial() -> [u8; 20] {
    let mut serial = [0u8; 20];
    serial[0] = 0x01;
    for (i, byte) in serial.iter_mut().enumerate().skip(1) {
        *byte = (i as u8).wrapping_mul(7);
    }
    serial
}

fn test_serial_2() -> [u8; 20] {
    let mut serial = [0u8; 20];
    serial[0] = 0x02;
    for (i, byte) in serial.iter_mut().enumerate().skip(1) {
        *byte = (i as u8).wrapping_mul(13);
    }
    serial
}

fn test_serial_3() -> [u8; 20] {
    let mut serial = [0u8; 20];
    serial[0] = 0x03;
    for (i, byte) in serial.iter_mut().enumerate().skip(1) {
        *byte = (i as u8).wrapping_mul(17);
    }
    serial
}

const NOT_BEFORE: &[u8; 15] = b"20250101000000Z";
const NOT_AFTER: &[u8; 15] = b"20350101000000Z";

const ROOT_CN: &str = "AZIHSM Root CA";
const INTER_CN: &str = "AZIHSM Intermediate CA";
const LEAF_CN: &str = "AZIHSM Attestation Key";
#[cfg(target_os = "linux")]
const DEVICE_CN: &str = "AZIHSM Device";

/// Test-local pad helper for CN (space-padded to CN_LEN).
fn pad_cn(cn: &str) -> [u8; CN_LEN] {
    let mut result = [b' '; CN_LEN];
    result[..cn.len()].copy_from_slice(cn.as_bytes());
    result
}

/// Test-local pad helper for SN (zero-padded to SN_LEN).
fn pad_sn(sn: &str) -> [u8; SN_LEN] {
    let mut result = [b'0'; SN_LEN];
    result[..sn.len()].copy_from_slice(sn.as_bytes());
    result
}

fn build_test_root_cert(key: &TestKeyPair) -> Vec<u8> {
    let params = RootCertParams {
        public_key: &key.pubkey_bytes,
        serial_number: &test_serial(),
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        subject_cn: ROOT_CN,
        subject_sn: "ROOTCA01",
        subject_key_id: &key.compute_ski(),
    };

    let mut tbs = azihsm_fw_hsm_std_x509::root_cert::TBS_TEMPLATE;
    patch_tbs_root(&mut tbs, &params);
    let (r, s) = key.sign_data(&tbs);

    let mut out = [0u8; 1024];
    let len = cert_builder::build_root_cert(&params, &r, &s, &mut out).unwrap();
    out[..len].to_vec()
}

fn patch_tbs_root(tbs: &mut [u8], params: &RootCertParams<'_>) {
    use azihsm_fw_hsm_std_x509::root_cert::*;
    let cn = pad_cn(params.subject_cn);
    let sn = pad_sn(params.subject_sn);
    tbs[PUBLIC_KEY_OFFSET..PUBLIC_KEY_OFFSET + 97].copy_from_slice(params.public_key);
    tbs[SERIAL_NUMBER_OFFSET..SERIAL_NUMBER_OFFSET + 20].copy_from_slice(params.serial_number);
    tbs[NOT_BEFORE_OFFSET..NOT_BEFORE_OFFSET + 15].copy_from_slice(params.not_before);
    tbs[NOT_AFTER_OFFSET..NOT_AFTER_OFFSET + 15].copy_from_slice(params.not_after);
    tbs[ISSUER_CN_OFFSET..ISSUER_CN_OFFSET + CN_LEN].copy_from_slice(&cn);
    tbs[SUBJECT_CN_OFFSET..SUBJECT_CN_OFFSET + CN_LEN].copy_from_slice(&cn);
    tbs[ISSUER_SN_OFFSET..ISSUER_SN_OFFSET + SN_LEN].copy_from_slice(&sn);
    tbs[SUBJECT_SN_OFFSET..SUBJECT_SN_OFFSET + SN_LEN].copy_from_slice(&sn);
    tbs[SUBJECT_KEY_ID_OFFSET..SUBJECT_KEY_ID_OFFSET + 20].copy_from_slice(params.subject_key_id);
}

fn build_test_intermediate_cert(
    inter_key: &TestKeyPair,
    root_key: &TestKeyPair,
    pathlen: u8,
) -> Vec<u8> {
    let params = IntermediateCertParams {
        public_key: &inter_key.pubkey_bytes,
        serial_number: &test_serial_2(),
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        subject_cn: INTER_CN,
        subject_sn: "INTERCA01",
        issuer_cn: ROOT_CN,
        issuer_sn: "ROOTCA01",
        subject_key_id: &inter_key.compute_ski(),
        authority_key_id: &root_key.compute_ski(),
        path_len: pathlen,
    };

    let mut tbs = azihsm_fw_hsm_std_x509::intermediate_cert::TBS_TEMPLATE;
    patch_tbs_intermediate(&mut tbs, &params);
    let (r, s) = root_key.sign_data(&tbs);

    let mut out = [0u8; 1024];
    let len = cert_builder::build_intermediate_cert(&params, &r, &s, &mut out).unwrap();
    out[..len].to_vec()
}

fn patch_tbs_intermediate(tbs: &mut [u8], params: &IntermediateCertParams<'_>) {
    use azihsm_fw_hsm_std_x509::intermediate_cert::*;
    let s_cn = pad_cn(params.subject_cn);
    let i_cn = pad_cn(params.issuer_cn);
    let s_sn = pad_sn(params.subject_sn);
    let i_sn = pad_sn(params.issuer_sn);
    tbs[PUBLIC_KEY_OFFSET..PUBLIC_KEY_OFFSET + 97].copy_from_slice(params.public_key);
    tbs[SERIAL_NUMBER_OFFSET..SERIAL_NUMBER_OFFSET + 20].copy_from_slice(params.serial_number);
    tbs[NOT_BEFORE_OFFSET..NOT_BEFORE_OFFSET + 15].copy_from_slice(params.not_before);
    tbs[NOT_AFTER_OFFSET..NOT_AFTER_OFFSET + 15].copy_from_slice(params.not_after);
    tbs[ISSUER_CN_OFFSET..ISSUER_CN_OFFSET + CN_LEN].copy_from_slice(&i_cn);
    tbs[SUBJECT_CN_OFFSET..SUBJECT_CN_OFFSET + CN_LEN].copy_from_slice(&s_cn);
    tbs[ISSUER_SN_OFFSET..ISSUER_SN_OFFSET + SN_LEN].copy_from_slice(&i_sn);
    tbs[SUBJECT_SN_OFFSET..SUBJECT_SN_OFFSET + SN_LEN].copy_from_slice(&s_sn);
    tbs[SUBJECT_KEY_ID_OFFSET..SUBJECT_KEY_ID_OFFSET + 20].copy_from_slice(params.subject_key_id);
    tbs[AUTHORITY_KEY_ID_OFFSET..AUTHORITY_KEY_ID_OFFSET + 20]
        .copy_from_slice(params.authority_key_id);
    tbs[PATH_LEN_OFFSET] = params.path_len;
}

fn build_test_leaf_cert(
    leaf_key: &TestKeyPair,
    issuer_key: &TestKeyPair,
    issuer_cn_str: &str,
    issuer_sn_str: &str,
    key_usage: KeyUsage,
) -> Vec<u8> {
    let params = LeafCertParams {
        public_key: &leaf_key.pubkey_bytes,
        serial_number: &test_serial_3(),
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        subject_cn: LEAF_CN,
        subject_sn: "LEAFKEY01",
        issuer_cn: issuer_cn_str,
        issuer_sn: issuer_sn_str,
        subject_key_id: &leaf_key.compute_ski(),
        authority_key_id: &issuer_key.compute_ski(),
        key_usage,
    };

    let mut tbs = azihsm_fw_hsm_std_x509::leaf_cert::TBS_TEMPLATE;
    patch_tbs_leaf(&mut tbs, &params);
    let (r, s) = issuer_key.sign_data(&tbs);

    let mut out = [0u8; 1024];
    let len = cert_builder::build_leaf_cert(&params, &r, &s, &mut out).unwrap();
    out[..len].to_vec()
}

fn patch_tbs_leaf(tbs: &mut [u8], params: &LeafCertParams<'_>) {
    use azihsm_fw_hsm_std_x509::leaf_cert::*;
    let s_cn = pad_cn(params.subject_cn);
    let i_cn = pad_cn(params.issuer_cn);
    let s_sn = pad_sn(params.subject_sn);
    let i_sn = pad_sn(params.issuer_sn);
    tbs[PUBLIC_KEY_OFFSET..PUBLIC_KEY_OFFSET + 97].copy_from_slice(params.public_key);
    tbs[SERIAL_NUMBER_OFFSET..SERIAL_NUMBER_OFFSET + 20].copy_from_slice(params.serial_number);
    tbs[NOT_BEFORE_OFFSET..NOT_BEFORE_OFFSET + 15].copy_from_slice(params.not_before);
    tbs[NOT_AFTER_OFFSET..NOT_AFTER_OFFSET + 15].copy_from_slice(params.not_after);
    tbs[ISSUER_CN_OFFSET..ISSUER_CN_OFFSET + CN_LEN].copy_from_slice(&i_cn);
    tbs[SUBJECT_CN_OFFSET..SUBJECT_CN_OFFSET + CN_LEN].copy_from_slice(&s_cn);
    tbs[ISSUER_SN_OFFSET..ISSUER_SN_OFFSET + SN_LEN].copy_from_slice(&i_sn);
    tbs[SUBJECT_SN_OFFSET..SUBJECT_SN_OFFSET + SN_LEN].copy_from_slice(&s_sn);
    tbs[SUBJECT_KEY_ID_OFFSET..SUBJECT_KEY_ID_OFFSET + 20].copy_from_slice(params.subject_key_id);
    tbs[AUTHORITY_KEY_ID_OFFSET..AUTHORITY_KEY_ID_OFFSET + 20]
        .copy_from_slice(params.authority_key_id);
    tbs[KEY_USAGE_OFFSET..KEY_USAGE_OFFSET + 2].copy_from_slice(&params.key_usage.to_bytes());
}

#[cfg(target_os = "linux")]
fn build_test_csr(key: &TestKeyPair) -> Vec<u8> {
    let subject_cn = pad_cn(DEVICE_CN);
    let subject_sn = pad_sn("DEVICE01");
    let params = DeviceCsrParams {
        public_key: &key.pubkey_bytes,
        subject_cn: DEVICE_CN,
        subject_sn: "DEVICE01",
    };

    let mut tbs = azihsm_fw_hsm_std_x509::device_csr::TBS_TEMPLATE;
    let pk_off = azihsm_fw_hsm_std_x509::device_csr::PUBLIC_KEY_OFFSET;
    let cn_off = azihsm_fw_hsm_std_x509::device_csr::SUBJECT_CN_OFFSET;
    let sn_off = azihsm_fw_hsm_std_x509::device_csr::SUBJECT_SN_OFFSET;
    tbs[pk_off..pk_off + 97].copy_from_slice(&key.pubkey_bytes);
    tbs[cn_off..cn_off + CN_LEN].copy_from_slice(&subject_cn);
    tbs[sn_off..sn_off + SN_LEN].copy_from_slice(&subject_sn);
    let (r, s) = key.sign_data(&tbs);

    let mut out = [0u8; 512];
    let len = csr_builder::build_device_csr(&params, &r, &s, &mut out).unwrap();
    out[..len].to_vec()
}

// =================== Individual Certificate Tests ===================

#[test]
fn test_root_cert_parses() {
    let root_key = TestKeyPair::generate();
    let cert_der = build_test_root_cert(&root_key);
    X509Certificate::from_der(&cert_der).expect("Root cert should parse as valid X509");
}

#[test]
fn test_root_cert_self_signed() {
    let root_key = TestKeyPair::generate();
    let cert_der = build_test_root_cert(&root_key);
    let cert = X509Certificate::from_der(&cert_der).unwrap();
    let result = cert.validate_chain(std::slice::from_ref(&cert)).unwrap();
    assert!(result, "Root cert should validate as self-signed");
}

#[cfg(target_os = "linux")]
#[test]
fn test_root_cert_extensions() {
    use openssl::nid::Nid;
    use openssl::x509::X509;

    let root_key = TestKeyPair::generate();
    let cert_der = build_test_root_cert(&root_key);
    let cert = X509::from_der(&cert_der).unwrap();

    assert_eq!(cert.version(), 2, "Should be v3 (version=2)");

    let ski = cert.subject_key_id().expect("SKI should exist");
    assert_eq!(ski.as_slice(), &root_key.compute_ski(), "SKI should match");

    let text = cert.to_text().unwrap();
    let text_str = String::from_utf8_lossy(&text);
    assert!(text_str.contains("CA:TRUE"), "Should contain CA:TRUE");
    assert!(
        text_str.contains("Certificate Sign"),
        "Should contain keyCertSign"
    );

    let subject = cert.subject_name();
    let cn_entry = subject.entries_by_nid(Nid::COMMONNAME).next().unwrap();
    let cn_str = cn_entry.data().as_utf8().unwrap().to_string();
    assert!(
        cn_str.starts_with(ROOT_CN),
        "CN should start with expected name"
    );
}

#[test]
fn test_intermediate_cert_parses() {
    let root_key = TestKeyPair::generate();
    let inter_key = TestKeyPair::generate();
    let cert_der = build_test_intermediate_cert(&inter_key, &root_key, 1);
    X509Certificate::from_der(&cert_der).expect("Intermediate cert should parse");
}

#[test]
fn test_intermediate_cert_signature() {
    let root_key = TestKeyPair::generate();
    let inter_key = TestKeyPair::generate();
    let cert_der = build_test_intermediate_cert(&inter_key, &root_key, 1);

    let root_der = build_test_root_cert(&root_key);
    let root_x509 = X509Certificate::from_der(&root_der).unwrap();
    let inter_x509 = X509Certificate::from_der(&cert_der).unwrap();
    let result = inter_x509.validate_chain(&[root_x509]).unwrap();
    assert!(result, "Intermediate cert should validate against root");
}

#[cfg(target_os = "linux")]
#[test]
fn test_intermediate_cert_extensions() {
    use openssl::x509::X509;

    let root_key = TestKeyPair::generate();
    let inter_key = TestKeyPair::generate();
    let cert_der = build_test_intermediate_cert(&inter_key, &root_key, 5);
    let cert = X509::from_der(&cert_der).unwrap();

    assert_eq!(cert.pathlen(), Some(5), "pathlen should be 5");

    let aki = cert.authority_key_id().expect("AKI should exist");
    assert_eq!(
        aki.as_slice(),
        &root_key.compute_ski(),
        "AKI should match root's SKI"
    );

    let ski = cert.subject_key_id().expect("SKI should exist");
    assert_eq!(ski.as_slice(), &inter_key.compute_ski(), "SKI should match");

    let text = cert.to_text().unwrap();
    let text_str = String::from_utf8_lossy(&text);
    assert!(text_str.contains("CA:TRUE"), "Should contain CA:TRUE");
}

#[test]
fn test_leaf_cert_parses() {
    let inter_key = TestKeyPair::generate();
    let leaf_key = TestKeyPair::generate();
    let cert_der = build_test_leaf_cert(
        &leaf_key,
        &inter_key,
        INTER_CN,
        "INTERCA01",
        KeyUsage::DIGITAL_SIGNATURE,
    );
    X509Certificate::from_der(&cert_der).expect("Leaf cert should parse");
}

#[test]
fn test_leaf_cert_signature() {
    let root_key = TestKeyPair::generate();
    let inter_key = TestKeyPair::generate();
    let leaf_key = TestKeyPair::generate();

    let root_der = build_test_root_cert(&root_key);
    let inter_der = build_test_intermediate_cert(&inter_key, &root_key, 0);
    let leaf_der = build_test_leaf_cert(
        &leaf_key,
        &inter_key,
        INTER_CN,
        "INTERCA01",
        KeyUsage::DIGITAL_SIGNATURE,
    );

    let root_x509 = X509Certificate::from_der(&root_der).unwrap();
    let inter_x509 = X509Certificate::from_der(&inter_der).unwrap();
    let leaf_x509 = X509Certificate::from_der(&leaf_der).unwrap();

    let result = leaf_x509.validate_chain(&[inter_x509, root_x509]).unwrap();
    assert!(result, "Leaf cert should validate against intermediate");
}

#[cfg(target_os = "linux")]
#[test]
fn test_leaf_cert_extensions() {
    use openssl::x509::X509;

    let inter_key = TestKeyPair::generate();
    let leaf_key = TestKeyPair::generate();
    let cert_der = build_test_leaf_cert(
        &leaf_key,
        &inter_key,
        INTER_CN,
        "INTERCA01",
        KeyUsage::DIGITAL_SIGNATURE,
    );
    let cert = X509::from_der(&cert_der).unwrap();

    let text = cert.to_text().unwrap();
    let text_str = String::from_utf8_lossy(&text);
    assert!(text_str.contains("CA:FALSE"), "Should contain CA:FALSE");
    assert!(
        text_str.contains("Digital Signature"),
        "Should show digitalSignature key usage"
    );
}

// =================== CSR Tests ===================

#[cfg(target_os = "linux")]
#[test]
fn test_csr_parses() {
    use openssl::x509::X509Req;
    let key = TestKeyPair::generate();
    let csr_der = build_test_csr(&key);
    X509Req::from_der(&csr_der).expect("CSR should parse");
}

#[cfg(target_os = "linux")]
#[test]
fn test_csr_signature() {
    use openssl::x509::X509Req;
    let key = TestKeyPair::generate();
    let csr_der = build_test_csr(&key);
    let csr = X509Req::from_der(&csr_der).unwrap();
    let pkey = csr.public_key().unwrap();
    assert!(
        csr.verify(&pkey).unwrap(),
        "CSR should verify against its own key"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn test_csr_subject() {
    use openssl::nid::Nid;
    use openssl::x509::X509Req;
    let key = TestKeyPair::generate();
    let csr_der = build_test_csr(&key);
    let csr = X509Req::from_der(&csr_der).unwrap();
    let subject = csr.subject_name();
    let cn_entry = subject.entries_by_nid(Nid::COMMONNAME).next().unwrap();
    let cn_str = cn_entry.data().as_utf8().unwrap().to_string();
    assert!(
        cn_str.starts_with(DEVICE_CN),
        "CSR CN should start with expected device name"
    );
}

// =================== Chain Validation Tests (Critical) ===================

#[test]
fn test_chain_root_to_leaf() {
    let root_key = TestKeyPair::generate();
    let leaf_key = TestKeyPair::generate();

    let root_der = build_test_root_cert(&root_key);
    // Leaf signed directly by root (issuer CN = root CN)
    let leaf_der = build_test_leaf_cert(
        &leaf_key,
        &root_key,
        ROOT_CN,
        "ROOTCA01",
        KeyUsage::DIGITAL_SIGNATURE,
    );

    let root_x509 = X509Certificate::from_der(&root_der).unwrap();
    let leaf_x509 = X509Certificate::from_der(&leaf_der).unwrap();

    let result = leaf_x509.validate_chain(&[root_x509]).unwrap();
    assert!(result, "Root -> Leaf chain should validate");
}

#[test]
fn test_chain_root_intermediate_leaf() {
    let root_key = TestKeyPair::generate();
    let inter_key = TestKeyPair::generate();
    let leaf_key = TestKeyPair::generate();

    let root_der = build_test_root_cert(&root_key);
    let inter_der = build_test_intermediate_cert(&inter_key, &root_key, 0);
    let leaf_der = build_test_leaf_cert(
        &leaf_key,
        &inter_key,
        INTER_CN,
        "INTERCA01",
        KeyUsage::DIGITAL_SIGNATURE,
    );

    let root_x509 = X509Certificate::from_der(&root_der).unwrap();
    let inter_x509 = X509Certificate::from_der(&inter_der).unwrap();
    let leaf_x509 = X509Certificate::from_der(&leaf_der).unwrap();

    let result = leaf_x509.validate_chain(&[inter_x509, root_x509]).unwrap();
    assert!(result, "Root -> Intermediate -> Leaf chain should validate");
}

#[test]
fn test_chain_wrong_signer_fails() {
    let root_key = TestKeyPair::generate();
    let wrong_key = TestKeyPair::generate();
    let leaf_key = TestKeyPair::generate();

    let root_der = build_test_root_cert(&root_key);

    let leaf_params = LeafCertParams {
        public_key: &leaf_key.pubkey_bytes,
        serial_number: &test_serial_3(),
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        subject_cn: LEAF_CN,
        issuer_cn: ROOT_CN,
        subject_sn: "LEAFKEY01",
        issuer_sn: "ROOTCA01",
        subject_key_id: &leaf_key.compute_ski(),
        authority_key_id: &root_key.compute_ski(),
        key_usage: KeyUsage::DIGITAL_SIGNATURE,
    };

    let mut tbs = azihsm_fw_hsm_std_x509::leaf_cert::TBS_TEMPLATE;
    patch_tbs_leaf(&mut tbs, &leaf_params);
    let (r, s) = wrong_key.sign_data(&tbs);

    let mut out = [0u8; 1024];
    let len = cert_builder::build_leaf_cert(&leaf_params, &r, &s, &mut out).unwrap();
    let leaf_der = out[..len].to_vec();

    let root_x509 = X509Certificate::from_der(&root_der).unwrap();
    let leaf_x509 = X509Certificate::from_der(&leaf_der).unwrap();

    let result = leaf_x509.validate_chain(&[root_x509]);
    assert!(
        result.is_err() || !result.unwrap(),
        "Chain with wrong signer should fail"
    );
}

#[test]
fn test_chain_intermediate_pathlen_0() {
    let root_key = TestKeyPair::generate();
    let inter_key = TestKeyPair::generate();
    let leaf_key = TestKeyPair::generate();

    let root_der = build_test_root_cert(&root_key);
    let inter_der = build_test_intermediate_cert(&inter_key, &root_key, 0);
    let leaf_der = build_test_leaf_cert(
        &leaf_key,
        &inter_key,
        INTER_CN,
        "INTERCA01",
        KeyUsage::DIGITAL_SIGNATURE,
    );

    let root_x509 = X509Certificate::from_der(&root_der).unwrap();
    let inter_x509 = X509Certificate::from_der(&inter_der).unwrap();
    let leaf_x509 = X509Certificate::from_der(&leaf_der).unwrap();

    let result = leaf_x509.validate_chain(&[inter_x509, root_x509]).unwrap();
    assert!(
        result,
        "pathlen:0 intermediate should be able to sign leaf certs"
    );
}

// =================== Field Patching Tests ===================

#[cfg(target_os = "linux")]
#[test]
fn test_serial_number_patched() {
    use openssl::x509::X509;

    let root_key = TestKeyPair::generate();
    let cert_der = build_test_root_cert(&root_key);
    let cert = X509::from_der(&cert_der).unwrap();
    let serial = cert.serial_number().to_bn().unwrap();
    let serial_bytes = serial.to_vec();
    assert_eq!(
        serial_bytes[0], 0x01,
        "Serial number first byte should match"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn test_public_key_patched() {
    use openssl::ec::EcGroup;
    use openssl::nid::Nid;
    use openssl::x509::X509;

    let root_key = TestKeyPair::generate();
    let cert_der = build_test_root_cert(&root_key);
    let cert = X509::from_der(&cert_der).unwrap();
    let pubkey = cert.public_key().unwrap();
    let ec_key = pubkey.ec_key().unwrap();
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let actual_bytes = ec_key
        .public_key()
        .to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )
        .unwrap();
    assert_eq!(
        actual_bytes,
        root_key.pubkey_bytes.as_slice(),
        "Public key should match"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn test_subject_sn_patched() {
    use openssl::nid::Nid;
    use openssl::x509::X509;

    let root_key = TestKeyPair::generate();
    let cert_der = build_test_root_cert(&root_key);
    let cert = X509::from_der(&cert_der).unwrap();
    let subject = cert.subject_name();
    let sn_entry = subject.entries_by_nid(Nid::SERIALNUMBER).next().unwrap();
    let sn_str = sn_entry.data().as_utf8().unwrap().to_string();
    let binding = pad_sn("ROOTCA01");
    let expected = std::str::from_utf8(&binding).unwrap();
    assert_eq!(sn_str, expected, "Subject serialNumber should match");
}

#[cfg(target_os = "linux")]
#[test]
fn test_issuer_sn_patched() {
    use openssl::nid::Nid;
    use openssl::x509::X509;

    let root_key = TestKeyPair::generate();
    let inter_key = TestKeyPair::generate();
    let cert_der = build_test_intermediate_cert(&inter_key, &root_key, 0);
    let cert = X509::from_der(&cert_der).unwrap();
    let issuer = cert.issuer_name();
    let sn_entry = issuer.entries_by_nid(Nid::SERIALNUMBER).next().unwrap();
    let sn_str = sn_entry.data().as_utf8().unwrap().to_string();
    let binding = pad_sn("ROOTCA01");
    let expected = std::str::from_utf8(&binding).unwrap();
    assert_eq!(sn_str, expected, "Issuer serialNumber should match");
}

#[test]
fn test_invalid_serial_rejected() {
    let root_key = TestKeyPair::generate();
    let mut serial = test_serial();
    serial[0] = 0x80;

    let params = RootCertParams {
        public_key: &root_key.pubkey_bytes,
        serial_number: &serial,
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        subject_cn: ROOT_CN,
        subject_sn: "ROOTCA01",
        subject_key_id: &root_key.compute_ski(),
    };

    let r = [0u8; 48];
    let s = [0u8; 48];
    let mut out = [0u8; 1024];
    let result = cert_builder::build_root_cert(&params, &r, &s, &mut out);
    assert!(result.is_none(), "Serial with bit 7 set should be rejected");
}

// =================== CN/SN Validation Tests ===================
// These test that the builders reject invalid CN/SN inputs.

#[test]
fn test_cn_too_long_rejected() {
    let root_key = TestKeyPair::generate();
    let name = "A".repeat(33);
    let params = RootCertParams {
        public_key: &root_key.pubkey_bytes,
        serial_number: &test_serial(),
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        subject_cn: &name,
        subject_sn: "ROOTCA01",
        subject_key_id: &root_key.compute_ski(),
    };
    let r = [0u8; 48];
    let s = [0u8; 48];
    let mut out = [0u8; 1024];
    assert!(cert_builder::build_root_cert(&params, &r, &s, &mut out).is_none());
}

#[test]
fn test_cn_non_ascii_rejected() {
    let root_key = TestKeyPair::generate();
    let params = RootCertParams {
        public_key: &root_key.pubkey_bytes,
        serial_number: &test_serial(),
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        subject_cn: "Ünîcödé",
        subject_sn: "ROOTCA01",
        subject_key_id: &root_key.compute_ski(),
    };
    let r = [0u8; 48];
    let s = [0u8; 48];
    let mut out = [0u8; 1024];
    assert!(cert_builder::build_root_cert(&params, &r, &s, &mut out).is_none());
}

#[test]
fn test_sn_too_long_rejected() {
    let root_key = TestKeyPair::generate();
    let long_sn = "A".repeat(65);
    let params = RootCertParams {
        public_key: &root_key.pubkey_bytes,
        serial_number: &test_serial(),
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        subject_cn: ROOT_CN,
        subject_sn: &long_sn,
        subject_key_id: &root_key.compute_ski(),
    };
    let r = [0u8; 48];
    let s = [0u8; 48];
    let mut out = [0u8; 1024];
    assert!(cert_builder::build_root_cert(&params, &r, &s, &mut out).is_none());
}
