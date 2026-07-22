// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Security-domain provisioning fixture for the api-level sealing round
//! trip.
//!
//! Drives the full flow through the public `azihsm_api` surface — rotate
//! the CO PSK, `part_init_ex`, build a POTA-anchored PTA chain,
//! `part_final_ex` — to reach the `Initialized` state `SdSealingKeyGen`
//! requires. The chain is built on the host with [`azihsm_crypto`],
//! mirroring the wire-level `ddi/tbor/types/tests/harness/x509_fixture.rs`.

use azihsm_api::*;
use azihsm_crypto::EccCurve;
use azihsm_crypto::EccKeyOp;
use azihsm_crypto::EccPrivateKey;
use azihsm_crypto::EcdsaAlgo;
use azihsm_crypto::HashAlgo;
use azihsm_crypto::HashOp;
use azihsm_crypto::SignOp;
use azihsm_crypto::x509_builder::cert_builder;
use azihsm_crypto::x509_builder::cert_builder::CN_LEN;
use azihsm_crypto::x509_builder::cert_builder::IntermediateCertParams;
use azihsm_crypto::x509_builder::cert_builder::RootCertParams;
use azihsm_crypto::x509_builder::cert_builder::SN_LEN;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::POLICY_INFO_LEN;
use azihsm_ddi_tbor_types::POLICY_MAX_KEY_LEN;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::PolicyPubKey;
use azihsm_ddi_tbor_types::PolicyVer;
use azihsm_ddi_tbor_types::SATA_THUMBPRINT_LEN;
use zerocopy::IntoBytes;

use crate::emu_helpers::fresh_emu_partition;

const SEC1_PUB_LEN: usize = 97;
const RAW_PUB_LEN: usize = 96;
const NOT_BEFORE: &[u8; 15] = b"20250101000000Z";
const NOT_AFTER: &[u8; 15] = b"20350101000000Z";
const ROOT_CN: &str = "AZIHSM POTA Root CA";
const ROOT_SN: &str = "POTAROOT1";
const PTA_CN: &str = "AZIHSM PTA Intermediate CA";
const PTA_SN: &str = "PTAINT001";

/// A fixed non-default CO PSK used to clear the default-PSK gate.
const ROTATED_CO_PSK: [u8; PSK_LEN] = [
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
    0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
];

/// A synthetic P-384 CA key (the policy POTA trust anchor) that signs
/// certificates and exposes its public key.
struct CaKey {
    private_key: EccPrivateKey,
    pub_sec1: [u8; SEC1_PUB_LEN],
}

impl CaKey {
    /// Generate a fresh P-384 CA key.
    fn generate() -> Self {
        let private_key = EccPrivateKey::from_curve(EccCurve::P384).expect("P-384 key");
        let (x, y) = private_key.coord_vec().expect("coords");
        let mut pub_sec1 = [0u8; SEC1_PUB_LEN];
        pub_sec1[0] = 0x04;
        pub_sec1[1..49].copy_from_slice(&x);
        pub_sec1[49..97].copy_from_slice(&y);
        Self {
            private_key,
            pub_sec1,
        }
    }

    /// Raw `X ‖ Y` (96-byte) public coordinates — the policy `POTAPubKey`
    /// form.
    fn raw_pub(&self) -> [u8; RAW_PUB_LEN] {
        self.pub_sec1[1..].try_into().expect("raw pub")
    }

    /// SHA-1 of the SEC1 public key — the Subject Key Identifier.
    fn ski(&self) -> [u8; 20] {
        sha1_ski(&self.pub_sec1)
    }

    /// ECDSA-P384 / SHA-384 sign `tbs`, returning `(r, s)` (48 bytes each).
    fn sign(&self, tbs: &[u8]) -> ([u8; 48], [u8; 48]) {
        // A raw P-384 ECDSA signature is always 96 bytes (r ‖ s); sign
        // once into a fixed buffer.
        let mut algo = EcdsaAlgo::new(HashAlgo::sha384());
        let mut sig = [0u8; 96];
        let written = algo
            .sign(&self.private_key, tbs, Some(&mut sig))
            .expect("sign");
        assert_eq!(written, 96, "P-384 raw signature is 96 bytes");
        let mut r = [0u8; 48];
        let mut s = [0u8; 48];
        r.copy_from_slice(&sig[..48]);
        s.copy_from_slice(&sig[48..]);
        (r, s)
    }
}

/// SHA-1 of a SEC1 public key (Subject / Authority Key Identifier).
fn sha1_ski(sec1: &[u8; SEC1_PUB_LEN]) -> [u8; 20] {
    let mut algo = HashAlgo::sha1();
    let mut out = [0u8; 20];
    algo.hash(sec1, Some(&mut out)).expect("sha1");
    out
}

/// A 20-byte positive DER serial number seeded from `tag`.
fn serial(tag: u8) -> [u8; 20] {
    let mut s = [0u8; 20];
    s[0] = tag & 0x7F;
    for (i, b) in s.iter_mut().enumerate().skip(1) {
        *b = tag.wrapping_add(i as u8);
    }
    s
}

/// Pad a common name to the template's fixed CN field width.
fn pad_cn(cn: &str) -> [u8; CN_LEN] {
    let mut out = [b' '; CN_LEN];
    out[..cn.len()].copy_from_slice(cn.as_bytes());
    out
}

/// Pad a serial-number string to the template's fixed SN field width.
fn pad_sn(sn: &str) -> [u8; SN_LEN] {
    let mut out = [b'0'; SN_LEN];
    out[..sn.len()].copy_from_slice(sn.as_bytes());
    out
}

/// A generated PTA chain (root -> PTA), DER-encoded, root-first.
struct PtaChain {
    root_der: Vec<u8>,
    pta_der: Vec<u8>,
}

/// Build a self-signed POTA root CA certificate (DER).
fn build_root(ca: &CaKey) -> Vec<u8> {
    let params = RootCertParams {
        public_key: &ca.pub_sec1,
        serial_number: &serial(1),
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        subject_cn: ROOT_CN,
        subject_sn: ROOT_SN,
        subject_key_id: &ca.ski(),
    };
    let mut tbs = azihsm_crypto::x509_builder::root_cert::TBS_TEMPLATE;
    patch_tbs_root(&mut tbs, &params);
    let (r, s) = ca.sign(&tbs);
    let mut out = vec![0u8; 1024];
    let len = cert_builder::build_root_cert(&params, &r, &s, &mut out).expect("root cert");
    out.truncate(len);
    out
}

/// Build the PTA intermediate CA certificate carrying the partition PTA
/// key (`pta_pub_sec1`), signed by `issuer` (the POTA CA).
fn build_pta_intermediate(pta_pub_sec1: &[u8; SEC1_PUB_LEN], issuer: &CaKey) -> Vec<u8> {
    let params = IntermediateCertParams {
        public_key: pta_pub_sec1,
        serial_number: &serial(2),
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        subject_cn: PTA_CN,
        subject_sn: PTA_SN,
        issuer_cn: ROOT_CN,
        issuer_sn: ROOT_SN,
        subject_key_id: &sha1_ski(pta_pub_sec1),
        authority_key_id: &issuer.ski(),
        path_len: 0,
    };
    let mut tbs = azihsm_crypto::x509_builder::intermediate_cert::TBS_TEMPLATE;
    patch_tbs_intermediate(&mut tbs, &params);
    let (r, s) = issuer.sign(&tbs);
    let mut out = vec![0u8; 1024];
    let len =
        cert_builder::build_intermediate_cert(&params, &r, &s, &mut out).expect("PTA intermediate");
    out.truncate(len);
    out
}

/// Build a POTA-anchored root -> PTA chain from the partition PTA key.
fn make_pta_chain(pota_ca: &CaKey, pta_pub_sec1: &[u8; SEC1_PUB_LEN]) -> PtaChain {
    PtaChain {
        root_der: build_root(pota_ca),
        pta_der: build_pta_intermediate(pta_pub_sec1, pota_ca),
    }
}

/// Extract the SEC1 uncompressed public key (`0x04 ‖ X ‖ Y`) from a DER
/// PKCS#10 CSR.
fn pta_pub_from_csr(csr: &[u8]) -> [u8; SEC1_PUB_LEN] {
    let (_, cr, _) = der_tlv(csr); // CertificationRequest
    let (_, cri, _) = der_tlv(cr); // certificationRequestInfo
    let (_, _version, after_version) = der_tlv(cri);
    let (_, _subject, after_subject) = der_tlv(after_version);
    let (_, spki, _) = der_tlv(after_subject);
    let (_, _algorithm, after_algorithm) = der_tlv(spki);
    let (tag, bit_string, _) = der_tlv(after_algorithm);
    assert_eq!(tag, 0x03, "subjectPublicKey must be a BIT STRING");
    // Drop the leading unused-bits octet; `get` avoids an OOB slice on a
    // truncated BIT STRING.
    let point = bit_string
        .get(1..)
        .expect("BIT STRING missing unused-bits octet");
    assert_eq!(point.len(), SEC1_PUB_LEN, "P-384 uncompressed point");
    assert_eq!(point[0], 0x04, "uncompressed point tag");
    point.try_into().expect("SEC1 point")
}

/// Read one DER TLV: returns `(tag, contents, rest)`. Panics with a clear
/// message (rather than an out-of-bounds slice) if `der` is truncated.
fn der_tlv(der: &[u8]) -> (u8, &[u8], &[u8]) {
    assert!(der.len() >= 2, "DER TLV: missing tag/length octet");
    let tag = der[0];
    let len_octet = der[1];
    let (len, header) = if len_octet & 0x80 == 0 {
        (usize::from(len_octet), 2)
    } else {
        let n = usize::from(len_octet & 0x7F);
        assert!(der.len() >= 2 + n, "DER TLV: truncated long-form length");
        let mut len = 0usize;
        for &b in &der[2..2 + n] {
            len = (len << 8) | usize::from(b);
        }
        (len, 2 + n)
    };
    assert!(der.len() >= header + len, "DER TLV: truncated content");
    (tag, &der[header..header + len], &der[header + len..])
}

/// Patch a root-cert TBS template with the variable field values.
fn patch_tbs_root(tbs: &mut [u8], params: &RootCertParams<'_>) {
    use azihsm_crypto::x509_builder::root_cert::*;
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

/// Patch an intermediate-cert TBS template with the variable field values.
fn patch_tbs_intermediate(tbs: &mut [u8], params: &IntermediateCertParams<'_>) {
    use azihsm_crypto::x509_builder::intermediate_cert::*;
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

/// Build a unified `PartPolicy` binding the real POTA public key, so
/// `part_final_ex` can validate a chain anchored to it. SATA carries a
/// filler key (not chain-validated in this flow).
fn part_policy_with_pota(pota_raw: &[u8; RAW_PUB_LEN]) -> PartPolicy {
    let mut sata = [0u8; POLICY_MAX_KEY_LEN];
    for (i, b) in sata.iter_mut().enumerate() {
        *b = (0x20u8.wrapping_add(i as u8)) | 0x80;
    }
    PartPolicy {
        version: PolicyVer { major: 1, minor: 0 },
        pota_pub_key: PolicyPubKey::new(PolicyKeyKind::Ecc384, RAW_PUB_LEN as u16, *pota_raw),
        sata_pub_key: PolicyPubKey::new(PolicyKeyKind::Ecc384, RAW_PUB_LEN as u16, sata),
        info: [0xAB; POLICY_INFO_LEN],
        ..PartPolicy::zeroed()
    }
}

/// Deterministic machine-seed fixture.
fn mach_seed() -> [u8; MACH_SEED_LEN] {
    let mut v = [0u8; MACH_SEED_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = 0x40 + i as u8;
    }
    v
}

/// Deterministic POTA thumbprint fixture (stored, not chain-validated).
fn pota_thumbprint() -> [u8; POTA_THUMBPRINT_LEN] {
    let mut v = [0u8; POTA_THUMBPRINT_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = 0x80 ^ i as u8;
    }
    v
}

/// Deterministic SATA thumbprint fixture (stored, not chain-validated).
fn sata_thumbprint() -> [u8; SATA_THUMBPRINT_LEN] {
    let mut v = [0u8; SATA_THUMBPRINT_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = 0x40 ^ i as u8;
    }
    v
}

/// Provision a fresh partition's security domain and return a live,
/// provisioned Crypto-Officer session (`Initialized` state).
///
/// Bootstrap CO under the default PSK, rotate it, reopen under the rotated
/// PSK, `part_init_ex`, build a POTA-anchored PTA chain from the CSR, then
/// `part_final_ex`.
pub(crate) fn finalized_co_session() -> HsmSession {
    let (part, rev) = fresh_emu_partition();

    // Bootstrap the CO session under the default PSK and rotate it; the
    // bootstrap session closes on drop at the end of this block.
    {
        let bootstrap = part
            .open_session_ex(
                rev,
                HsmSessionPsk::new(HsmPskId::CO),
                HsmSessionExType::Authenticated,
            )
            .expect("open bootstrap CO session");
        bootstrap
            .change_psk(&ROTATED_CO_PSK)
            .expect("rotate CO PSK");
    }

    let session = part
        .open_session_ex(
            rev,
            HsmSessionPsk::with_psk(HsmPskId::CO, &ROTATED_CO_PSK),
            HsmSessionExType::Authenticated,
        )
        .expect("open rotated CO session");

    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());
    let policy_bytes = policy.as_bytes();
    let init = session
        .part_init_ex(
            &mach_seed(),
            policy_bytes,
            &pota_thumbprint(),
            &sata_thumbprint(),
            None,
        )
        .expect("part_init_ex");

    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    let certs = [
        HsmCert {
            cert: &chain.root_der,
        },
        HsmCert {
            cert: &chain.pta_der,
        },
    ];
    session
        .part_final_ex(policy_bytes, &certs, None)
        .expect("part_final_ex");

    session
}
