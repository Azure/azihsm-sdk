// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cross-platform X.509 certificate-chain fixtures for TBOR integration tests.
//!
//! `PartFinal` validates that the supplied PTA certificate chain is
//! anchored to the policy `POTAPubKey` and that its leaf public key is the
//! partition's PTA key. These helpers build such a chain on the host with
//! [`azihsm_crypto`] (key generation + ECDSA-P384 signing, cross-platform
//! CNG on Windows / OpenSSL on Linux) and the
//! [`azihsm_crypto::x509_builder`] TBS templates, so the emu tests exercise
//! the real firmware `x509-chain` validator end to end without depending on
//! any `fw` crate or on OpenSSL directly.

use azihsm_crypto::x509_builder::cert_builder;
use azihsm_crypto::x509_builder::cert_builder::IntermediateCertParams;
use azihsm_crypto::x509_builder::cert_builder::KeyUsage;
use azihsm_crypto::x509_builder::cert_builder::LeafCertParams;
use azihsm_crypto::x509_builder::cert_builder::RootCertParams;
use azihsm_crypto::x509_builder::cert_builder::CN_LEN;
use azihsm_crypto::x509_builder::cert_builder::SN_LEN;
use azihsm_crypto::EccCurve;
use azihsm_crypto::EccKeyOp;
use azihsm_crypto::EccPrivateKey;
use azihsm_crypto::EcdsaAlgo;
use azihsm_crypto::HashAlgo;
use azihsm_crypto::HashOp;
use azihsm_crypto::SignOp;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;

/// Length of a SEC1 uncompressed P-384 point (`0x04 ‖ X ‖ Y`).
pub const SEC1_PUB_LEN: usize = 97;

/// Length of a raw P-384 public point (`X ‖ Y`, big-endian, no tag).
pub const RAW_PUB_LEN: usize = 96;

const NOT_BEFORE: &[u8; 15] = b"20250101000000Z";
const NOT_AFTER: &[u8; 15] = b"20350101000000Z";
const ROOT_CN: &str = "AZIHSM POTA Root CA";
const ROOT_SN: &str = "POTAROOT1";
const LEAF_CN: &str = "AZIHSM Evidence Leaf";
const LEAF_SN: &str = "EVLEAF001";

/// Fixed PTA `commonName` prefix (mirrors the firmware `PTA_SUBJECT_CN`).
const PTA_SUBJECT_CN_PREFIX: &str = "Azure Integrated HSM PTA";
/// Domain-separation label for the PTAID digest (mirrors firmware `PTAID_LABEL`).
const PTAID_LABEL: &[u8] = b"AZIHSM-PTAID-v1";
/// PTAID digest bytes hex-encoded into the `commonName`.
const PTAID_LEN: usize = 16;
/// Length of the PTA single-`commonName(64)` Name SEQUENCE DER.
const PTA_SUBJECT_DER_LEN: usize = 13 + 64;
/// Fixed DER prefix of the single-`commonName(64)` Name SEQUENCE.
const PTA_SUBJECT_DER_PREFIX: [u8; 13] = [
    0x30, 0x4b, 0x31, 0x49, 0x30, 0x47, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x40,
];

/// A synthetic P-384 CA key (e.g. a policy POTA trust anchor) that can
/// sign certificates and expose its public key.
pub struct CaKey {
    private_key: EccPrivateKey,
    pub_sec1: [u8; SEC1_PUB_LEN],
}

impl CaKey {
    /// Generate a fresh P-384 CA key.
    pub fn generate() -> Self {
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

    /// Raw `X ‖ Y` (96-byte, big-endian) public coordinates — the form a
    /// policy `pota_pub_key` stores.
    pub fn raw_pub(&self) -> [u8; RAW_PUB_LEN] {
        self.pub_sec1[1..].try_into().expect("raw pub")
    }

    /// SEC1 uncompressed public key (`0x04 ‖ X ‖ Y`, 97 bytes).
    pub fn sec1_pub(&self) -> [u8; SEC1_PUB_LEN] {
        self.pub_sec1
    }

    /// SHA-1 of the SEC1 public key — the Subject Key Identifier.
    fn ski(&self) -> [u8; 20] {
        sha1_ski(&self.pub_sec1)
    }

    /// ECDSA-P384 / SHA-384 sign `tbs`, returning `(r, s)` (48 bytes each).
    fn sign(&self, tbs: &[u8]) -> ([u8; 48], [u8; 48]) {
        let mut algo = EcdsaAlgo::new(HashAlgo::sha384());
        let len = algo.sign(&self.private_key, tbs, None).expect("sig len");
        let mut sig = vec![0u8; len];
        let written = algo
            .sign(&self.private_key, tbs, Some(&mut sig))
            .expect("sign");
        assert_eq!(written, 96, "P-384 raw signature is 96 bytes");
        let mut r = [0u8; 48];
        let mut s = [0u8; 48];
        r.copy_from_slice(&sig[..48]);
        s.copy_from_slice(&sig[48..96]);
        (r, s)
    }
}

/// Reusable POTA root fixture for tests that provision a partition.
///
/// Owns the POTA signing key, its self-signed root certificate, and the
/// certificate thumbprint supplied to `PartInit`. Command tests remain
/// responsible for constructing their command-specific partition policy.
pub struct PotaFixture {
    ca: CaKey,
    root_der: Vec<u8>,
    thumbprint: [u8; POTA_THUMBPRINT_LEN],
}

impl PotaFixture {
    /// Generate a P-384 POTA key and its self-signed root certificate.
    pub fn generate() -> Self {
        let ca = CaKey::generate();
        let root_der = build_root(&ca);
        let thumbprint = sha384(&root_der);
        Self {
            ca,
            root_der,
            thumbprint,
        }
    }

    /// Raw POTA public coordinates for the partition policy.
    pub fn raw_pub(&self) -> [u8; RAW_PUB_LEN] {
        self.ca.raw_pub()
    }

    /// SHA-384 thumbprint of the self-signed POTA root certificate.
    pub fn thumbprint(&self) -> &[u8; POTA_THUMBPRINT_LEN] {
        &self.thumbprint
    }

    /// Issue a root-to-PTA chain for the partition PTA public key.
    pub fn chain_for(&self, pta_pub_sec1: &[u8; SEC1_PUB_LEN]) -> PtaChain {
        PtaChain {
            root_der: self.root_der.clone(),
            pta_der: build_pta_intermediate(pta_pub_sec1, &self.ca),
        }
    }
}

/// SHA-384 of a DER certificate (POTA root thumbprint).
fn sha384(input: &[u8]) -> [u8; POTA_THUMBPRINT_LEN] {
    let mut hash = HashAlgo::sha384();
    let mut out = [0u8; POTA_THUMBPRINT_LEN];
    hash.hash(input, Some(&mut out)).expect("SHA-384");
    out
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
    s[0] = tag & 0x7F; // positive INTEGER (bit 7 clear)
    for (i, b) in s.iter_mut().enumerate().skip(1) {
        *b = tag.wrapping_add(i as u8);
    }
    s
}

fn pad_cn(cn: &str) -> [u8; CN_LEN] {
    let mut out = [b' '; CN_LEN];
    out[..cn.len()].copy_from_slice(cn.as_bytes());
    out
}

fn pad_sn(sn: &str) -> [u8; SN_LEN] {
    let mut out = [b'0'; SN_LEN];
    out[..sn.len()].copy_from_slice(sn.as_bytes());
    out
}

/// Build a self-signed Root CA certificate for `ca` (DER).
pub fn build_root(ca: &CaKey) -> Vec<u8> {
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

/// Build the PTA intermediate CA certificate whose subject public key is
/// `pta_pub_sec1` (the partition PTA key), signed by `issuer` (the POTA
/// CA).  The PTA is a CA cert (`cA=true`), **not** an end-entity leaf.
///
/// The subject is the deterministic single-`commonName(64)` PTA profile the
/// firmware stamps (derived from `pta_pub_sec1`), and the SKID is
/// SHA-1(SEC1 PTA key), so the issued PTA certificate satisfies the profile
/// `PartFinal` enforces and anchors the firmware's on-demand slot-2 PID leaf.
pub fn build_pta_intermediate(pta_pub_sec1: &[u8; SEC1_PUB_LEN], issuer: &CaKey) -> Vec<u8> {
    build_pta_cert(
        pta_pub_sec1,
        issuer,
        &pta_subject_der(pta_pub_sec1),
        &sha1_ski(pta_pub_sec1),
    )
}

/// Derive the deterministic PTA subject Name DER from the SEC1 PTA public
/// key, mirroring the firmware's PTAID derivation
/// (`fw/core/lib/src/ddi/tbor/pta.rs`): the subject is a single
/// `commonName(64)` RDN holding the fixed PTA name, a separating space, and
/// the lowercase-hex PTAID (`SHA-384(PTAID_LABEL ‖ SEC1 key)[..16]`),
/// space-padded.  This equals the subject a conformant CA preserves from
/// the `PartInit` CSR, and the issuer the firmware stamps on its PID leaf.
pub fn pta_subject_der(sec1_pub: &[u8; SEC1_PUB_LEN]) -> [u8; PTA_SUBJECT_DER_LEN] {
    let mut input = Vec::with_capacity(PTAID_LABEL.len() + SEC1_PUB_LEN);
    input.extend_from_slice(PTAID_LABEL);
    input.extend_from_slice(sec1_pub);
    let mut algo = HashAlgo::sha384();
    let mut digest = [0u8; 48];
    algo.hash(&input, Some(&mut digest)).expect("sha384");

    let mut cn = [b' '; 64];
    cn[..PTA_SUBJECT_CN_PREFIX.len()].copy_from_slice(PTA_SUBJECT_CN_PREFIX.as_bytes());
    let hex = b"0123456789abcdef";
    let base = PTA_SUBJECT_CN_PREFIX.len() + 1;
    for (i, byte) in digest[..PTAID_LEN].iter().enumerate() {
        cn[base + 2 * i] = hex[usize::from(byte >> 4)];
        cn[base + 2 * i + 1] = hex[usize::from(byte & 0x0f)];
    }

    let mut der = [0u8; PTA_SUBJECT_DER_LEN];
    der[..PTA_SUBJECT_DER_PREFIX.len()].copy_from_slice(&PTA_SUBJECT_DER_PREFIX);
    der[PTA_SUBJECT_DER_PREFIX.len()..].copy_from_slice(&cn);
    der
}

/// Build a POTA-signed PTA intermediate CA certificate for `pta_pub_sec1`
/// with a caller-chosen subject Name DER and SKID.  The subject and SKID
/// are the two profile fields `PartFinal` pins against the deterministic
/// PTA profile, so rejection tests use this to craft well-formed,
/// POTA-anchored chains that violate exactly one of them.
fn build_pta_cert(
    pta_pub_sec1: &[u8; SEC1_PUB_LEN],
    issuer: &CaKey,
    subject: &[u8],
    subject_key_id: &[u8; 20],
) -> Vec<u8> {
    let params = IntermediateCertParams {
        public_key: pta_pub_sec1,
        serial_number: &serial(2),
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        subject_cn: "",
        subject_sn: "",
        issuer_cn: ROOT_CN,
        issuer_sn: ROOT_SN,
        subject_key_id,
        authority_key_id: &issuer.ski(),
        path_len: 0,
    };

    let mut tbs = [0u8; 1024];
    let tbs_len = cert_builder::intermediate_cert_tbs_with_subject_name(&params, subject, &mut tbs)
        .expect("PTA subject");
    let (r, s) = issuer.sign(&tbs[..tbs_len]);

    let mut out = vec![0u8; 1024];
    let len = cert_builder::assemble_cert(&tbs[..tbs_len], &r, &s, &mut out).expect("PTA cert");
    out.truncate(len);
    out
}

/// A generated PTA chain, root → PTA intermediate, DER-encoded.
pub struct PtaChain {
    /// Self-signed POTA root CA certificate (DER).
    pub root_der: Vec<u8>,
    /// PTA intermediate CA certificate carrying the partition PTA key (DER).
    pub pta_der: Vec<u8>,
}

impl PtaChain {
    /// The chain's certificate DERs in root → PTA order, ready to hand to
    /// `PartFinal` as out-of-band items.
    pub fn der_items(&self) -> [&[u8]; 2] {
        [self.root_der.as_slice(), self.pta_der.as_slice()]
    }
}

/// Build a root→PTA chain: a self-signed root CA (`pota_ca`, whose public
/// key is the policy `POTAPubKey`) certifying a PTA intermediate CA that
/// carries `pta_pub_sec1` (the partition PTA key, e.g. learned from the
/// `PartInit` CSR).
pub fn make_pta_chain(pota_ca: &CaKey, pta_pub_sec1: &[u8; SEC1_PUB_LEN]) -> PtaChain {
    PtaChain {
        root_der: build_root(pota_ca),
        pta_der: build_pta_intermediate(pta_pub_sec1, pota_ca),
    }
}

/// Build a root→PTA chain that preserves the exact DER subject Name from
/// the `PartInit` CSR (and the SHA-1 SKID over the PTA key).  A conformant
/// CA signs the CSR as presented, so the issued PTA certificate's subject
/// equals the deterministic profile the firmware stamps as the issuer of
/// its on-demand slot-2 PID leaf — the only configuration under which that
/// leaf's chain validates.
pub fn make_pta_chain_csr_subject(pota_ca: &CaKey, csr: &[u8]) -> PtaChain {
    let pta_pub = pta_pub_from_csr(csr);
    let subject = pta_subject_from_csr(csr);
    PtaChain {
        root_der: build_root(pota_ca),
        pta_der: build_pta_cert(&pta_pub, pota_ca, subject, &sha1_ski(&pta_pub)),
    }
}

/// Build a POTA-anchored root→PTA chain that carries the correct partition
/// PTA key but a **wrong subject** (the conformant single-CN(64) profile
/// derived from a different key), so finalization's PTA-profile check
/// rejects it with `PartFinalPtaMismatch`.
pub fn make_pta_chain_wrong_subject(
    pota_ca: &CaKey,
    pta_pub_sec1: &[u8; SEC1_PUB_LEN],
) -> PtaChain {
    let wrong_subject = pta_subject_der(&CaKey::generate().sec1_pub());
    PtaChain {
        root_der: build_root(pota_ca),
        pta_der: build_pta_cert(
            pta_pub_sec1,
            pota_ca,
            &wrong_subject,
            &sha1_ski(pta_pub_sec1),
        ),
    }
}

/// Build a POTA-anchored root→PTA chain that carries the correct partition
/// PTA key and the conformant subject but a **wrong Subject Key Identifier**
/// (not SHA-1 of the SEC1 PTA key), so finalization's PTA-profile check
/// rejects it with `PartFinalPtaMismatch`.
pub fn make_pta_chain_wrong_skid(pota_ca: &CaKey, pta_pub_sec1: &[u8; SEC1_PUB_LEN]) -> PtaChain {
    PtaChain {
        root_der: build_root(pota_ca),
        pta_der: build_pta_cert(
            pta_pub_sec1,
            pota_ca,
            &pta_subject_der(pta_pub_sec1),
            &[0xAB; 20],
        ),
    }
}

/// Build a POTA-anchored root→PTA chain whose **self-signed root CA
/// constrains the certification path to zero** (`pathLenConstraint == 0`),
/// leaving no depth budget for the PTA to go on and issue the firmware's
/// on-demand slot-2 PID leaf.  Every other property is conformant — correct
/// POTA anchor, partition PTA key, and PTA subject/SKID/CA profile — so
/// finalization must reject the chain solely on the ancestor path-length
/// constraint (`X509PathLenExceeded`) now that it validates the terminal
/// PTA as an issuing CA.
pub fn make_pta_chain_constrained_root(
    pota_ca: &CaKey,
    pta_pub_sec1: &[u8; SEC1_PUB_LEN],
) -> PtaChain {
    PtaChain {
        root_der: build_constrained_root(pota_ca),
        pta_der: build_pta_intermediate(pta_pub_sec1, pota_ca),
    }
}

/// Build a self-signed POTA root CA certificate identical in identity to
/// [`build_root`] (same CN/SN and SKID, so a conformant PTA still chains to
/// it) but carrying `pathLenConstraint == 0`, i.e. it may certify
/// end-entity leaves only, never a further issuing CA.  The root template
/// used by [`build_root`] omits `pathLenConstraint`, so this reuses the
/// intermediate-certificate builder (which emits one) with a subject Name
/// equal to its issuer Name to keep the certificate self-signed.
fn build_constrained_root(ca: &CaKey) -> Vec<u8> {
    let subject = root_issuer_name_der();

    let params = IntermediateCertParams {
        public_key: &ca.pub_sec1,
        serial_number: &serial(1),
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        subject_cn: "",
        subject_sn: "",
        issuer_cn: ROOT_CN,
        issuer_sn: ROOT_SN,
        subject_key_id: &ca.ski(),
        authority_key_id: &ca.ski(),
        path_len: 0,
    };

    let mut tbs = [0u8; 1024];
    let tbs_len =
        cert_builder::intermediate_cert_tbs_with_subject_name(&params, &subject, &mut tbs)
            .expect("constrained root subject");
    let (r, s) = ca.sign(&tbs[..tbs_len]);

    let mut out = vec![0u8; 1024];
    let len =
        cert_builder::assemble_cert(&tbs[..tbs_len], &r, &s, &mut out).expect("constrained root");
    out.truncate(len);
    out
}

/// Reproduce the exact issuer Name DER the intermediate-certificate builder
/// stamps for the shared root identity (`ROOT_CN` / `ROOT_SN`).  Feeding
/// this back as the subject Name yields `issuer == subject`, the byte-for-
/// byte equality the chain validator requires of a self-signed root.
fn root_issuer_name_der() -> Vec<u8> {
    use azihsm_crypto::x509_builder::intermediate_cert;

    let mut tbs = intermediate_cert::TBS_TEMPLATE;
    tbs[intermediate_cert::ISSUER_CN_OFFSET..][..intermediate_cert::ISSUER_CN_LEN]
        .copy_from_slice(&pad_cn(ROOT_CN));
    tbs[intermediate_cert::ISSUER_SN_OFFSET..][..intermediate_cert::ISSUER_SN_LEN]
        .copy_from_slice(&pad_sn(ROOT_SN));

    // The issuer `Name` is a short-form DER `SEQUENCE` beginning 13 header
    // bytes (SEQUENCE/SET/SEQUENCE/OID/UTF8String) before the CN value; its
    // total span is the 2-byte header plus the length declared in the
    // header's length byte.
    const NAME_HEADER_PREFIX: usize = 13;
    let start = intermediate_cert::ISSUER_CN_OFFSET - NAME_HEADER_PREFIX;
    let len = 2 + usize::from(tbs[start + 1]);
    tbs[start..start + len].to_vec()
}
/// `leaf_pub_sec1` (e.g. an attestation-report signer's key), signed by
/// `issuer` (a self-signed CA).  Unlike [`build_pta_intermediate`], the
/// leaf is `cA=false` with `digitalSignature` key usage.
pub fn build_leaf(leaf_pub_sec1: &[u8; SEC1_PUB_LEN], issuer: &CaKey) -> Vec<u8> {
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

/// A generated root→leaf attestation-evidence chain, DER-encoded.
///
/// `root_der` is a self-signed CA certificate; `leaf_der` is an
/// end-entity certificate signed by the root whose subject public key is
/// the caller-supplied report-signer key.
pub struct GeneratedChain {
    /// Self-signed root CA certificate (DER).
    pub root_der: Vec<u8>,
    /// End-entity leaf certificate carrying the report-signer key (DER).
    pub leaf_der: Vec<u8>,
}

impl GeneratedChain {
    /// The chain's certificate DERs in root → leaf order.
    pub fn der_items(&self) -> [&[u8]; 2] {
        [self.root_der.as_slice(), self.leaf_der.as_slice()]
    }
}

/// Build a root→leaf chain: a self-signed root CA (`ca`) certifying an
/// end-entity leaf that carries `leaf_pub_raw` (raw `X ‖ Y`, the report
/// signer's public key).
///
/// Pass a caller-controlled `ca` (e.g. the SATA anchor key) when the chain
/// must be anchored to a known public key; otherwise use a fresh
/// [`CaKey::generate`].
pub fn make_chain(ca: &CaKey, leaf_pub_raw: &[u8; RAW_PUB_LEN]) -> GeneratedChain {
    let mut leaf_sec1 = [0u8; SEC1_PUB_LEN];
    leaf_sec1[0] = 0x04;
    leaf_sec1[1..].copy_from_slice(leaf_pub_raw);
    GeneratedChain {
        root_der: build_root(ca),
        leaf_der: build_leaf(&leaf_sec1, ca),
    }
}

/// Extract the SEC1 public key (`0x04 ‖ X ‖ Y`, 97 bytes) from a DER
/// PKCS#10 CSR, parsed structurally per
/// [RFC 2986](https://datatracker.ietf.org/doc/html/rfc2986):
///
/// ```text
/// CertificationRequest ::= SEQUENCE {
///     certificationRequestInfo SEQUENCE {
///         version                 INTEGER,
///         subject                 Name,
///         subjectPKInfo           SEQUENCE {
///             algorithm           AlgorithmIdentifier,
///             subjectPublicKey     BIT STRING },   -- 00 ‖ 04 ‖ X ‖ Y
///         attributes          [0] IMPLICIT ... },
///     signatureAlgorithm       AlgorithmIdentifier,
///     signature                BIT STRING }
/// ```
///
/// This is the receiver's "convert CSR → certificate" step: read the
/// requested public key so the POTA CA can issue the PTA cert for it.
pub fn pta_pub_from_csr(csr: &[u8]) -> [u8; SEC1_PUB_LEN] {
    // CertificationRequest ::= SEQUENCE
    let (_, cr, _) = der_tlv(csr);
    // certificationRequestInfo ::= SEQUENCE (first field of the request)
    let (_, cri, _) = der_tlv(cr);
    // version INTEGER
    let (_, _version, after_version) = der_tlv(cri);
    // subject Name ::= SEQUENCE
    let (_, _subject, after_subject) = der_tlv(after_version);
    // subjectPKInfo ::= SEQUENCE { algorithm, subjectPublicKey }
    let (_, spki, _) = der_tlv(after_subject);
    // algorithm AlgorithmIdentifier ::= SEQUENCE
    let (_, _algorithm, after_algorithm) = der_tlv(spki);
    // subjectPublicKey BIT STRING
    let (tag, bit_string, _) = der_tlv(after_algorithm);
    assert_eq!(tag, 0x03, "subjectPublicKey must be a BIT STRING");
    // BIT STRING content: leading unused-bits octet (0), then the SEC1
    // uncompressed point (0x04 ‖ X ‖ Y).
    let point = &bit_string[1..];
    assert_eq!(point.len(), SEC1_PUB_LEN, "P-384 uncompressed point");
    assert_eq!(point[0], 0x04, "uncompressed point tag");
    point.try_into().expect("SEC1 point")
}

/// Extract the complete DER subject Name (SEQUENCE TLV) from a PKCS#10
/// CSR, without interpreting its profile.  Used to reissue a PTA cert that
/// preserves the subject the firmware deterministically stamps.
pub fn pta_subject_from_csr(csr: &[u8]) -> &[u8] {
    let (_, cr, _) = der_tlv(csr);
    let (_, cri, _) = der_tlv(cr);
    let (_, _version, after_version) = der_tlv(cri);
    let (_, _subject, after_subject) = der_tlv(after_version);
    &after_version[..after_version.len() - after_subject.len()]
}

/// Read one DER TLV at the start of `der`, returning `(tag, contents,
/// rest)`.  Supports short- and long-form definite lengths (sufficient
/// for the small CSRs the firmware emits).
fn der_tlv(der: &[u8]) -> (u8, &[u8], &[u8]) {
    let tag = der[0];
    let len_octet = der[1];
    let (len, header) = if len_octet & 0x80 == 0 {
        (usize::from(len_octet), 2)
    } else {
        let n = usize::from(len_octet & 0x7F);
        let mut len = 0usize;
        for &b in &der[2..2 + n] {
            len = (len << 8) | usize::from(b);
        }
        (len, 2 + n)
    };
    (tag, &der[header..header + len], &der[header + len..])
}

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
