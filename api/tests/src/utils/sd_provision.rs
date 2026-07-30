// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Security-domain provisioning fixture shared by the api-level sealing
//! and backup tests.
//!
//! Drives the full flow through the public `azihsm_api` surface (rotate
//! the CO PSK, `part_init_ex`, POTA-anchored PTA chain, `part_final_ex`)
//! to reach the `Initialized` state, plus the evidence-chain and
//! sealing-key helpers the backup tests need. Certificates are built on
//! the host with [`azihsm_crypto`], mirroring the wire-level
//! `ddi/tbor/types/tests/harness/x509_fixture.rs`.

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
use azihsm_crypto::x509_builder::cert_builder::KeyUsage;
use azihsm_crypto::x509_builder::cert_builder::LeafCertParams;
use azihsm_crypto::x509_builder::cert_builder::RootCertParams;
use azihsm_crypto::x509_builder::cert_builder::SN_LEN;
use azihsm_ddi_tbor_types::KEY_REPORT_DATA_LEN;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POLICY_INFO_LEN;
use azihsm_ddi_tbor_types::POLICY_MAX_KEY_LEN;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::PolicyFlags;
use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::PolicyPubKey;
use azihsm_ddi_tbor_types::PolicyVer;
use azihsm_ddi_tbor_types::SATA_THUMBPRINT_LEN;
use zerocopy::IntoBytes;

use crate::utils::partition_ex_helpers::new_partition;

const SEC1_PUB_LEN: usize = 97;
pub(crate) const RAW_PUB_LEN: usize = 96;
const NOT_BEFORE: &[u8; 15] = b"20250101000000Z";
const NOT_AFTER: &[u8; 15] = b"20350101000000Z";
const ROOT_CN: &str = "AZIHSM POTA Root CA";
const ROOT_SN: &str = "POTAROOT1";
const PTA_CN: &str = "AZIHSM PTA Intermediate CA";
const PTA_SN: &str = "PTAINT001";
const LEAF_CN: &str = "AZIHSM Evidence Leaf";
const LEAF_SN: &str = "EVLEAF001";

/// Byte offset of the SATA public-key **data** inside the `PartPolicy`
/// image: `sata_pub_key` starts at 102 (`kind(2) ‖ len(2) ‖ data(96)`),
/// so the raw `X ‖ Y` coordinates begin at 106.
const OFF_SATA_PUB_KEY_DATA: usize = 106;

/// Byte offsets of the backing-partition fields inside the `PartPolicy`
/// image (mirror of `fw/core/ddi/tbor/types/src/policy.rs`).
const OFF_BACKUP_PART_ID: usize = 302;
const OFF_BACKUP_PART_PUB_KEY: usize = 318;
const BACKUP_PART_ID_LEN: usize = 16;

/// A fixed non-default CO PSK used to clear the default-PSK gate.
const ROTATED_CO_PSK: [u8; PSK_LEN] = [
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
    0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
];

/// A synthetic P-384 CA key (the policy POTA trust anchor) that signs
/// certificates and exposes its public key.
pub(crate) struct CaKey {
    private_key: EccPrivateKey,
    pub_sec1: [u8; SEC1_PUB_LEN],
}

impl CaKey {
    /// Generate a fresh P-384 CA key.
    pub(crate) fn generate() -> Self {
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
    pub(crate) fn raw_pub(&self) -> [u8; RAW_PUB_LEN] {
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

/// Build an **end-entity** leaf certificate whose subject public key is
/// `leaf_pub_sec1` (an attestation-report signer's key), signed by
/// `issuer` (a self-signed CA). Unlike [`build_pta_intermediate`], the
/// leaf is `cA=false` with `digitalSignature` key usage.
fn build_leaf(leaf_pub_sec1: &[u8; SEC1_PUB_LEN], issuer: &CaKey) -> Vec<u8> {
    let params = LeafCertParams {
        public_key: leaf_pub_sec1,
        serial_number: &serial(3),
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        subject_cn: LEAF_CN,
        subject_sn: LEAF_SN,
        issuer_cn: ROOT_CN,
        issuer_sn: ROOT_SN,
        subject_key_id: &sha1_ski(leaf_pub_sec1),
        authority_key_id: &issuer.ski(),
        key_usage: KeyUsage::DIGITAL_SIGNATURE,
    };
    let mut tbs = azihsm_crypto::x509_builder::leaf_cert::TBS_TEMPLATE;
    patch_tbs_leaf(&mut tbs, &params);
    let (r, s) = issuer.sign(&tbs);
    let mut out = vec![0u8; 1024];
    let len = cert_builder::build_leaf_cert(&params, &r, &s, &mut out).expect("leaf cert");
    out.truncate(len);
    out
}

/// A generated root -> leaf attestation-evidence chain, DER-encoded.
///
/// `root_der` is a self-signed CA certificate; `leaf_der` is an
/// end-entity certificate signed by the root whose subject public key is
/// the caller-supplied report-signer key.
pub(crate) struct GeneratedChain {
    root_der: Vec<u8>,
    leaf_der: Vec<u8>,
}

/// Build a root -> leaf chain: a self-signed root CA (`ca`) certifying an
/// end-entity leaf that carries `leaf_pub_raw` (raw `X ‖ Y`, the report
/// signer's public key).
///
/// Pass a caller-controlled `ca` (e.g. the SATA anchor key) when the chain
/// must be anchored to a known public key; otherwise use a fresh
/// [`CaKey::generate`].
fn make_chain(ca: &CaKey, leaf_pub_raw: &[u8; RAW_PUB_LEN]) -> GeneratedChain {
    let mut leaf_sec1 = [0u8; SEC1_PUB_LEN];
    leaf_sec1[0] = 0x04;
    leaf_sec1[1..].copy_from_slice(leaf_pub_raw);
    GeneratedChain {
        root_der: build_root(ca),
        leaf_der: build_leaf(&leaf_sec1, ca),
    }
}

/// Patch a leaf-cert TBS template with the variable field values.
fn patch_tbs_leaf(tbs: &mut [u8], params: &LeafCertParams<'_>) {
    use azihsm_crypto::x509_builder::leaf_cert::*;
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
        // Enable peer cloning so this one backing policy also drives the
        // `SdCreatePeerBackup` / `SdRestorePeerBackup` tests; the flag is
        // inert for the remote/reseal/restore commands, which don't gate on
        // it.
        flags: PolicyFlags::new().with_allow_peer_cloning(true),
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
    let (part, rev) = new_partition();

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

/// Build a policy naming **this** partition as the backing partition
/// (`backup_part_id = PID`, `backup_part_pub_key = PID public key`) and
/// anchoring the security domain to `sata_pub` (raw `X ‖ Y`).
///
/// The caller learns the PID / PID public key from `PartInfo` before
/// `part_init_ex`; the SATA key is the trust anchor the test also uses to
/// sign the partition-owner certificate chain.
fn backing_part_policy(
    pid: &[u8],
    pid_pub: &[u8],
    sata_pub: &[u8; RAW_PUB_LEN],
    pota_pub: &[u8; RAW_PUB_LEN],
) -> [u8; PART_POLICY_LEN] {
    // Anchor the policy to a real POTA key so `part_final_ex` can validate
    // a PTA certificate chain against it.
    let policy = part_policy_with_pota(pota_pub);
    let mut bytes = [0u8; PART_POLICY_LEN];
    bytes.copy_from_slice(policy.as_bytes());

    // Overwrite the placeholder SATA key with the anchor's real P-384
    // coordinates (kind / len already Ecc384 / 96).
    bytes[OFF_SATA_PUB_KEY_DATA..OFF_SATA_PUB_KEY_DATA + RAW_PUB_LEN].copy_from_slice(sata_pub);

    bytes[OFF_BACKUP_PART_ID..OFF_BACKUP_PART_ID + BACKUP_PART_ID_LEN].copy_from_slice(pid);

    // backup_part_pub_key = { kind: Ecc384 (LE), len: 96 (LE), data }.
    let off = OFF_BACKUP_PART_PUB_KEY;
    bytes[off..off + 2].copy_from_slice(&PolicyKeyKind::Ecc384.0.to_le_bytes());
    bytes[off + 2..off + 4].copy_from_slice(&(POLICY_MAX_KEY_LEN as u16).to_le_bytes());
    bytes[off + 4..off + 4 + POLICY_MAX_KEY_LEN].copy_from_slice(pid_pub);

    bytes
}

/// Owns the DER bytes for the receiver's three evidence chains and the
/// attestation report, so a borrowed [`HsmSdEvidence`] can reference them.
pub(crate) struct SdEvidence {
    mfgr: GeneratedChain,
    owner: GeneratedChain,
    part_owner: GeneratedChain,
    report: Vec<u8>,
}

impl SdEvidence {
    /// Manufacturer chain as an ordered `[root, leaf]` cert list.
    pub(crate) fn mfgr_certs(&self) -> [HsmCert<'_>; 2] {
        [
            HsmCert {
                cert: &self.mfgr.root_der,
            },
            HsmCert {
                cert: &self.mfgr.leaf_der,
            },
        ]
    }

    /// Owner chain as an ordered `[root, leaf]` cert list.
    pub(crate) fn owner_certs(&self) -> [HsmCert<'_>; 2] {
        [
            HsmCert {
                cert: &self.owner.root_der,
            },
            HsmCert {
                cert: &self.owner.leaf_der,
            },
        ]
    }

    /// Partition-owner chain as an ordered `[root, leaf]` cert list.
    pub(crate) fn part_owner_certs(&self) -> [HsmCert<'_>; 2] {
        [
            HsmCert {
                cert: &self.part_owner.root_der,
            },
            HsmCert {
                cert: &self.part_owner.leaf_der,
            },
        ]
    }

    /// The COSE_Sign1 attestation-report DER bytes.
    pub(crate) fn report(&self) -> &[u8] {
        &self.report
    }

    /// Build a borrowed [`HsmSdEvidence`] over this party's three cert
    /// chains and report and pass it to `f`. The cert arrays live only for
    /// the call, so the evidence is delivered through a closure.
    pub(crate) fn with_hsm_evidence<R>(&self, f: impl FnOnce(&HsmSdEvidence<'_>) -> R) -> R {
        let mfgr = self.mfgr_certs();
        let owner = self.owner_certs();
        let part_owner = self.part_owner_certs();
        f(&HsmSdEvidence {
            mfgr_cert_chain: &mfgr,
            owner_cert_chain: &owner,
            part_owner_cert_chain: &part_owner,
            report: self.report(),
        })
    }
}

/// Build the receiver's three-chain evidence for `pid_pub`: manufacturer
/// and owner chains rooted at fresh CAs, and a partition-owner chain rooted
/// at the policy `sata_key`. Every leaf certifies `pid_pub` (the report
/// signer), so all three share one leaf key.
pub(crate) fn build_receiver_evidence(
    pid_pub: &[u8; RAW_PUB_LEN],
    sata_key: &CaKey,
    report: &[u8],
) -> SdEvidence {
    SdEvidence {
        mfgr: make_chain(&CaKey::generate(), pid_pub),
        owner: make_chain(&CaKey::generate(), pid_pub),
        part_owner: make_chain(sata_key, pid_pub),
        report: report.to_vec(),
    }
}

/// Provision a factory-reset backing partition anchored to the shared
/// `sata_key`/`pota`. When `policy_in` is `None` the policy is built from
/// this partition's `PartInfo` identity; on the restore path the caller
/// reuses the first incarnation's policy so both agree on the domain image.
/// `prev_local_mk` restores `PartLocalMK` during finalize — the reboot
/// recovery step that lets a captured masked sealing key unmask. Returns the
/// CO session, the policy image, the PID public key, and the
/// `local_mk_backup` that finalize produced.
pub(crate) fn provision_backing(
    sata_key: &CaKey,
    pota: &CaKey,
    policy_in: Option<[u8; PART_POLICY_LEN]>,
    prev_local_mk: Option<&[u8]>,
) -> (
    HsmSession,
    [u8; PART_POLICY_LEN],
    [u8; RAW_PUB_LEN],
    Vec<u8>,
) {
    let (part, rev) = new_partition();

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

    // PID / PID public key are materialized before part_init_ex.
    let pid = part.pid().expect("PartInfo PID");
    let pid_pub_vec = part.ex_pub_key().expect("PartInfo PID public key");
    assert_eq!(
        pid.len(),
        BACKUP_PART_ID_LEN,
        "PartInfo PID must be BACKUP_PART_ID_LEN bytes",
    );
    assert_eq!(
        pid_pub_vec.len(),
        RAW_PUB_LEN,
        "PartInfo PID public key must be RAW_PUB_LEN bytes",
    );
    let mut pid_pub = [0u8; RAW_PUB_LEN];
    pid_pub.copy_from_slice(&pid_pub_vec);

    let policy = policy_in.unwrap_or_else(|| {
        backing_part_policy(&pid, &pid_pub_vec, &sata_key.raw_pub(), &pota.raw_pub())
    });

    let init = session
        .part_init_ex(
            &mach_seed(),
            &policy,
            &pota_thumbprint(),
            &sata_thumbprint(),
            None,
        )
        .expect("part_init_ex");

    let chain = make_pta_chain(pota, &pta_pub_from_csr(&init.pta_csr));
    let certs = [
        HsmCert {
            cert: &chain.root_der,
        },
        HsmCert {
            cert: &chain.pta_der,
        },
    ];
    let result = session
        .part_final_ex(&policy, &certs, prev_local_mk)
        .expect("part_final_ex");

    (session, policy, pid_pub, result.local_mk_backup)
}

/// Provision a fresh partition with a **backing-partition policy** — one
/// that names this partition (via `PartInfo`) as the backup backing
/// partition and anchors the security domain to `sata_key` — and return
/// the live CO session, the exact policy image (needed verbatim by
/// `sd_create_remote_backup`), and the partition-identity public key that
/// every evidence leaf certificate must carry.
pub(crate) fn finalized_backing_session(
    sata_key: &CaKey,
) -> (HsmSession, [u8; PART_POLICY_LEN], [u8; RAW_PUB_LEN]) {
    let pota = CaKey::generate();
    let (session, policy, pid_pub, _local_mk) = provision_backing(sata_key, &pota, None, None);
    (session, policy, pid_pub)
}

/// Well-formed sealing key props: a `Sealing`-kind P-384 secret key
/// permitted for derivation only.
pub(crate) fn sealing_props() -> HsmKeyProps {
    HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Sealing)
        .bits(384)
        .can_derive(true)
        .build()
        .expect("build sealing props")
}

/// Mint an SD sealing key on `session` and return its masked blob and a
/// COSE_Sign1 `KeyReport` attesting it (signed by the PID key).
pub(crate) fn masked_key_and_report(session: &HsmSession) -> (Vec<u8>, Vec<u8>) {
    let mut algo = HsmSealingKeyGenAlgo::default();
    let key = HsmKeyManager::generate_key(session, &mut algo, sealing_props())
        .expect("generate sealing key");

    let masked = key.masked_key_vec().expect("masked key");

    let report_data = [0u8; KEY_REPORT_DATA_LEN];
    let report_len = key
        .generate_key_report(&report_data, None)
        .expect("key report size");
    let mut report = vec![0u8; report_len];
    let written = key
        .generate_key_report(&report_data, Some(&mut report))
        .expect("key report");
    report.truncate(written);

    (masked, report)
}
