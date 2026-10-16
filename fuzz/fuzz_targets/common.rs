// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared types and helpers for TBOR fuzz targets.

#![allow(dead_code)]

use azihsm_crypto::aead_envelope::AeadAlg;
use azihsm_crypto::*;
use azihsm_ddi::*;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_tbor_codec::Encoder;
use azihsm_ddi_tbor_codec::header::Header;
use azihsm_ddi_tbor_codec::*;
use azihsm_ddi_tbor_test_harness::CO_PSK_ID as CO;
use azihsm_ddi_tbor_test_harness::CU_PSK_ID as CU;
use azihsm_ddi_tbor_test_harness::SessionHandshake;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::x509_fixture::CaKey;
use azihsm_ddi_tbor_test_harness::x509_fixture::RAW_PUB_LEN;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_chain;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use azihsm_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use azihsm_ddi_tbor_types::AES_KEY_SIZE_128;
use azihsm_ddi_tbor_types::AES_KEY_SIZE_192;
use azihsm_ddi_tbor_types::AES_KEY_SIZE_256;
use azihsm_ddi_tbor_types::CertDescriptor;
use azihsm_ddi_tbor_types::ECC_CURVE_P256;
use azihsm_ddi_tbor_types::ECC_CURVE_P384;
use azihsm_ddi_tbor_types::ECC_CURVE_P521;
use azihsm_ddi_tbor_types::KEY_REPORT_DATA_LEN;
use azihsm_ddi_tbor_types::MACH_SEED_ENVELOPE_MAX_LEN;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POLICY_INFO_LEN;
use azihsm_ddi_tbor_types::POLICY_MAX_KEY_LEN;
use azihsm_ddi_tbor_types::POLICY_VERSION_MAJOR;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::PolicyPubKey;
use azihsm_ddi_tbor_types::PolicyVer;
use azihsm_ddi_tbor_types::ReportDescriptor;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborKeyReportReq;
use azihsm_ddi_tbor_types::TborPartInfoReq;
use azihsm_ddi_tbor_types::TborSdCreateRemoteBackupReq;
use azihsm_ddi_tbor_types::TborSdSealingKeyGenReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use zerocopy::TryFromBytes;

pub type DdiTest = AzihsmDdi;

/// Wire discriminants for the TBOR `KeyScope` enum.
pub const KEY_SCOPE_UNSPECIFIED: u8 = 0b000;
pub const KEY_SCOPE_SESSION: u8 = 0b001;
pub const KEY_SCOPE_EPHEMERAL: u8 = 0b010;
pub const KEY_SCOPE_LOCAL: u8 = 0b011;
pub const KEY_SCOPE_SECURITY_DOMAIN: u8 = 0b100;
pub const KEY_SCOPE_INTERNAL: u8 = 0b101;

/// TBOR key scopes (wire `KeyScope` discriminants) used by fuzz targets.
#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyScope {
    Unspecified,
    Session,
    Ephemeral,
    Local,
    SecurityDomain,
    Internal,
}

impl KeyScope {
    pub fn to_tbor(self) -> u8 {
        match self {
            Self::Unspecified => KEY_SCOPE_UNSPECIFIED,
            Self::Session => KEY_SCOPE_SESSION,
            Self::Ephemeral => KEY_SCOPE_EPHEMERAL,
            Self::Local => KEY_SCOPE_LOCAL,
            Self::SecurityDomain => KEY_SCOPE_SECURITY_DOMAIN,
            Self::Internal => KEY_SCOPE_INTERNAL,
        }
    }
}

/// Fuzz operations corresponding to the TOC builder methods on
/// [`Encoder`].
#[derive(Arbitrary, Debug)]
pub enum EncoderTOCBuilders {
    SessionId(u16),
    KeyId(u16),
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    Buffer(Vec<u8>),
    BufferReserve(u16),
    SealedKey(Vec<u8>),
    None,
    Padding(u16),
}

/// Which role's session to open for this iteration.
#[derive(Arbitrary, Debug)]
pub enum FuzzRole {
    /// `psk_id = 0`, `SessionType::Authenticated`
    Co,
    /// `psk_id = 1`, `SessionType::PlainText`
    Cu,
}

impl FuzzRole {
    pub fn psk_id(&self) -> u8 {
        match self {
            FuzzRole::Co => CO,
            FuzzRole::Cu => CU,
        }
    }

    pub fn session_type(&self) -> SessionType {
        match self {
            FuzzRole::Co => SessionType::Authenticated,
            FuzzRole::Cu => SessionType::PlainText,
        }
    }
}

/// TBOR ECC curves (wire `EccCurve` discriminants) for generated keys.
///
/// Shadows the `azihsm_crypto::EccCurve` glob import within this module.
#[derive(Arbitrary, Debug, Clone, Copy)]
pub enum EccCurve {
    P256,
    P384,
    P521,
}

impl EccCurve {
    pub fn to_tbor(self) -> u8 {
        match self {
            Self::P256 => ECC_CURVE_P256,
            Self::P384 => ECC_CURVE_P384,
            Self::P521 => ECC_CURVE_P521,
        }
    }

    /// Raw (unpadded) coordinate length in bytes; also the length of an
    /// ECDH shared secret (the X coordinate).
    pub fn coord_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }

    /// Largest digest the firmware zero-extends into the ECDSA field.
    pub fn max_digest_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 64,
        }
    }

    /// Wire `r ‖ s` length, each component padded to the coordinate width.
    pub fn wire_sig_len(self) -> usize {
        match self {
            Self::P256 => 64,
            Self::P384 => 96,
            Self::P521 => 136,
        }
    }

    /// Wire `x ‖ y` public-key length, each coordinate padded to the wire
    /// coordinate width (P-521: 66 -> 68 bytes).
    pub fn wire_pub_key_len(self) -> usize {
        match self {
            Self::P256 => 64,
            Self::P384 => 96,
            Self::P521 => 136,
        }
    }
}

/// TBOR AES key sizes supported by `AesGenerateKey`.
#[derive(Arbitrary, Debug)]
pub enum AesKeySize {
    Aes128,
    Aes192,
    Aes256,
}

impl AesKeySize {
    pub fn to_tbor(&self) -> u8 {
        match self {
            Self::Aes128 => AES_KEY_SIZE_128,
            Self::Aes192 => AES_KEY_SIZE_192,
            Self::Aes256 => AES_KEY_SIZE_256,
        }
    }
}

fn bounded_appended_bytes(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let len = usize::arbitrary(u)? % (MACH_SEED_ENVELOPE_MAX_LEN + 1);
    Ok(u.bytes(len)?.to_vec())
}

/// Post-seal mutation applied to a wire-valid `PartInit`
/// `mach_seed_envelope`.
///
/// `None` ships the sealed envelope untouched so the handler advances
/// past AEAD authentication into the policy / thumbprint / seed
/// pipeline. The other variants exercise the envelope parser's header,
/// AAD, ciphertext, tag, and length-reject paths without leaving them
/// buried under negligible-probability arbitrary-byte inputs.
#[derive(Arbitrary, Debug)]
pub enum EnvelopeMutation {
    /// Ship the sealed envelope unchanged.
    None,
    /// XOR a fuzzed mask into a fuzzed offset (offset wrapped modulo
    /// envelope length). Exercises AEAD tag / ciphertext tampering.
    FlipByte { offset: u16, mask: u8 },
    /// Truncate to `len % (envelope.len() + 1)` bytes. Exercises
    /// short-envelope rejects and post-decrypt length checks.
    Truncate { len: u16 },
    /// Append fuzzed trailing bytes (bounded) to exercise over-length
    /// rejects.
    Append(#[arbitrary(with = bounded_appended_bytes)] Vec<u8>),
}

impl EnvelopeMutation {
    pub fn apply(&self, envelope: &mut Vec<u8>) {
        match self {
            EnvelopeMutation::None => {}
            EnvelopeMutation::FlipByte { offset, mask } => {
                if !envelope.is_empty() && *mask != 0 {
                    let idx = (*offset as usize) % envelope.len();
                    envelope[idx] ^= *mask;
                }
            }
            EnvelopeMutation::Truncate { len } => {
                let cap = envelope.len() + 1;
                envelope.truncate((*len as usize) % cap);
            }
            EnvelopeMutation::Append(extra) => {
                envelope.extend_from_slice(extra);
            }
        }
    }

    /// `true` iff this mutation would leave the sealed envelope byte-
    /// identical (matches the `None` variant or a no-op offset/mask/len/
    /// extra choice inside a mutation variant). Drives the "expect
    /// success" classification for the result assertion.
    pub fn is_noop(&self, envelope: &[u8]) -> bool {
        match self {
            EnvelopeMutation::None => true,
            EnvelopeMutation::FlipByte { mask, .. } => *mask == 0 || envelope.is_empty(),
            EnvelopeMutation::Truncate { len } => {
                // `Vec::truncate(new_len)` only shrinks when `new_len <
                // envelope.len()`; `apply` computes
                // `len % (envelope.len() + 1)` so a no-op requires the
                // modulo to land on `envelope.len()`.
                (*len as usize) % (envelope.len() + 1) == envelope.len()
            }
            EnvelopeMutation::Append(extra) => extra.is_empty(),
        }
    }
}

/// Buffer size used by request encoder fuzz targets.
///
/// Sized to hold the worst-case request: a full header, the maximum number
/// of TOC entries (each a 4-byte / `u32` wire word), and the maximum data
/// section.
pub const FUZZ_REQ_BUF_SIZE: usize =
    REQ_HEADER_LEN + MAX_TOC_ENTRIES * TOC_ENTRY_LEN + MAX_DATA_SIZE;

/// Buffer size used by response encoder fuzz targets.
pub const FUZZ_RESP_BUF_SIZE: usize =
    RESP_HEADER_LEN + MAX_TOC_ENTRIES * TOC_ENTRY_LEN + MAX_DATA_SIZE;

static mut DEVICE_DISPLAY: bool = false;

pub fn common_fuzz_test(test: &dyn Fn(&TestCtx, &str)) {
    let ddi = DdiTest::default();
    let dev_infos = ddi.dev_info_list();
    if dev_infos.is_empty() {
        panic!("No devices found");
    }

    let path = match std::env::var("FUZZ_DEVICE") {
        Ok(path) => path,
        Err(_) => dev_infos.first().unwrap().path.clone(),
    };

    // Display all device paths and the selected device path if it hasn't been
    // displayed yet.
    unsafe {
        if !DEVICE_DISPLAY {
            for dev_info in &dev_infos {
                println!("Found device: {}", dev_info.path);
            }
            println!("Selected device: {}", path);
            DEVICE_DISPLAY = true;
        }
    }

    let ctx = TestCtx::new_primary_with_path(&path);

    test(&ctx, &path);
}

/// Two-phase AES-GCM-256 AEAD seal: size-query, allocate, then fill
pub fn seal_aead_envelope(key: &AesKey, iv: &[u8], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let total = aead_envelope::seal(AeadAlg::AesGcm256, key, iv, aad, pt, None)
        .expect("aead seal size query should succeed");
    let mut buf = vec![0u8; total];
    let written = aead_envelope::seal(AeadAlg::AesGcm256, key, iv, aad, pt, Some(&mut buf))
        .expect("aead seal should succeed");
    buf.truncate(written);
    buf
}

/// Apply a sequence of TOC builder operations to an encoder, returning
/// the encoded bytes on success or `None` if any step (including
/// [`Encoder::finish`]) fails.
pub fn run_encoder<'a, H: Header>(
    mut encoder: Encoder<'a, H>,
    ops: &[EncoderTOCBuilders],
) -> Option<&'a [u8]> {
    for op in ops {
        let result = match op {
            EncoderTOCBuilders::SessionId(id) => encoder.session_id(*id),
            EncoderTOCBuilders::KeyId(id) => encoder.key_id(*id),
            EncoderTOCBuilders::Uint8(v) => encoder.uint8(*v),
            EncoderTOCBuilders::Uint16(v) => encoder.uint16(*v),
            EncoderTOCBuilders::Uint32(v) => encoder.uint32(*v),
            EncoderTOCBuilders::Uint64(v) => encoder.uint64(*v),
            EncoderTOCBuilders::Buffer(data) => encoder.buffer(data),
            EncoderTOCBuilders::BufferReserve(len) => encoder.buffer_reserve(*len as usize),
            EncoderTOCBuilders::SealedKey(data) => encoder.sealed_key(data),
            EncoderTOCBuilders::None => encoder.none(),
            EncoderTOCBuilders::Padding(len) => encoder.padding(*len as usize),
        };
        match result {
            Ok(enc) => encoder = enc,
            Err(_) => return None,
        }
    }

    encoder.finish().ok()
}

pub fn validate_toc_entry(op: &EncoderTOCBuilders, entry: TocEntry<'_>) {
    match (op, entry) {
        (EncoderTOCBuilders::SessionId(expected), TocEntry::SessionId(actual)) => {
            assert_eq!(*expected, actual);
        }
        (EncoderTOCBuilders::KeyId(expected), TocEntry::KeyId(actual)) => {
            assert_eq!(*expected, actual);
        }
        (EncoderTOCBuilders::Uint8(expected), TocEntry::Uint8(actual)) => {
            assert_eq!(*expected, actual);
        }
        (EncoderTOCBuilders::Uint16(expected), TocEntry::Uint16(actual)) => {
            assert_eq!(*expected, actual);
        }
        (EncoderTOCBuilders::Uint32(expected), TocEntry::Uint32(actual)) => {
            assert_eq!(*expected, actual);
        }
        (EncoderTOCBuilders::Uint64(expected), TocEntry::Uint64(actual)) => {
            assert_eq!(*expected, actual);
        }
        (EncoderTOCBuilders::Buffer(expected), TocEntry::Buffer(actual)) => {
            assert_eq!(expected, actual);
        }
        (EncoderTOCBuilders::BufferReserve(expected), TocEntry::Buffer(actual)) => {
            assert_eq!(usize::from(*expected), actual.len());
        }
        (EncoderTOCBuilders::SealedKey(expected), TocEntry::SealedKey(actual)) => {
            assert_eq!(expected, actual);
        }
        (EncoderTOCBuilders::None, TocEntry::None) => {}
        (EncoderTOCBuilders::Padding(expected), TocEntry::Padding(actual)) => {
            assert_eq!(usize::from(*expected), actual.len());
            assert!(actual.iter().all(|byte| *byte == 0));
        }
        (expected, actual) => panic!("operation {expected:?} decoded as {actual:?}"),
    }
}

/// Fixed `PartInit` machine seed (`0x40 + i`), mirroring the canonical
/// fixture used by the `PartInit` integration suite.
pub fn mach_seed() -> [u8; MACH_SEED_LEN] {
    core::array::from_fn(|i| 0x40 + i as u8)
}

/// Fixed `PartInit` POTA thumbprint (`0x80 ^ i`), mirroring the canonical
/// fixture used by the `PartInit` integration suite.
pub fn pota_thumbprint() -> [u8; POTA_THUMBPRINT_LEN] {
    core::array::from_fn(|i| 0x80 ^ i as u8)
}

/// Fill a 96-byte `PolicyPubKey::data` slot with a deterministic
/// pattern seeded by `fill`: `(fill + i) | 0x80`.
///
/// Fuzz targets use this to synthesize wire-valid-but-cryptographically-
/// meaningless keys for policy slots the FW handler stores but does not
/// validate (the SATA anchor in both targets, and the POTA anchor for
/// `PartInit` where the chain walk never fires).
pub fn fill_ecc384_pubkey_pattern(fill: u8) -> [u8; POLICY_MAX_KEY_LEN] {
    let mut data = [0u8; POLICY_MAX_KEY_LEN];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (fill.wrapping_add(i as u8)) | 0x80;
    }
    data
}

/// Build a wire-valid `PartPolicy` blob that clears FW policy validation:
/// `version.major == POLICY_VERSION_MAJOR` and populated Ecc384 POTA +
/// SATA trust anchors. SAPOTA and backup-partition slots are left absent.
///
/// `pota_pub_key` is the raw 96-byte P-384 `X ‖ Y` POTA pubkey to embed:
/// `PartFinal` fuzz targets pass the real CA's raw pub (via
/// `CaKey::raw_pub`) so the cert-chain walk can validate against it;
/// `PartInit` fuzz targets pass a synthetic pattern (via
/// [`fill_ecc384_pubkey_pattern`]) because the chain walk never fires
/// there. The SATA slot is always filled with the `(0x20 + i) | 0x80`
/// pattern — the FW records it as a claim but the fuzz targets never
/// exercise a SATA chain, so any wire-valid Ecc384-shaped key suffices.
///
/// Uses the shared [`PartPolicy`] struct + typed [`PolicyPubKey`] /
/// [`PolicyVer`] constructors so the on-wire byte layout tracks whatever
/// the policy crate declares (no hand-computed field offsets here).
///
/// Constructs the policy directly from the wire-type's public fields
/// rather than the API-crate `PartPolicyBuilder`, so the fuzz package
/// keeps depending only on the low-level `azihsm_ddi_tbor_types` crate
/// (not the full `azihsm_api` stack).
pub fn known_good_part_policy(pota_pub_key: [u8; POLICY_MAX_KEY_LEN]) -> [u8; PART_POLICY_LEN] {
    use zerocopy::IntoBytes;

    let mut policy = PartPolicy::zeroed();
    policy.version = PolicyVer {
        major: POLICY_VERSION_MAJOR,
        minor: 0,
    };
    policy.pota_pub_key = PolicyPubKey::new(
        PolicyKeyKind::Ecc384,
        POLICY_MAX_KEY_LEN as u16,
        pota_pub_key,
    );
    policy.sata_pub_key = PolicyPubKey::new(
        PolicyKeyKind::Ecc384,
        POLICY_MAX_KEY_LEN as u16,
        fill_ecc384_pubkey_pattern(0x20),
    );
    policy.info = [0xAB; POLICY_INFO_LEN];

    let mut bytes = [0u8; PART_POLICY_LEN];
    bytes.copy_from_slice(policy.as_bytes());
    bytes
}

/// Drive `PartInit` → `PartFinal` so the partition is initialized and
/// partition-local masking keys are available to a fuzz target.
pub fn finalize_partition(ctx: &TestCtx, session: &SessionHandshake) {
    let pota = CaKey::generate();
    let policy = known_good_part_policy(pota.raw_pub());
    let init = ctx
        .part_init(session, &mach_seed(), &policy, &pota_thumbprint())
        .expect("PartInit should succeed");
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(session, &policy, &[], &chain.der_items())
        .expect("PartFinal should succeed");
}

fn add_evidence_item(oob_items: &mut Vec<Vec<u8>>, der: &[u8]) -> CertDescriptor {
    let index = u8::try_from(oob_items.len()).expect("evidence count fits descriptor index");
    let length = u16::try_from(der.len()).expect("evidence item length fits descriptor");
    oob_items.push(der.to_vec());
    CertDescriptor {
        index,
        length: length.into(),
    }
}

/// Initialize a partition and create a test security domain so its
/// masking key is available to a fuzz target.
pub fn create_test_security_domain(ctx: &TestCtx, session: &SessionHandshake) {
    use zerocopy::IntoBytes;

    let info = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo should succeed");
    let pid_pub: [u8; RAW_PUB_LEN] = info
        .pid_pub_key
        .as_slice()
        .try_into()
        .expect("PartInfo PID public key should have the expected length");
    let pota = CaKey::generate();
    let sata = CaKey::generate();
    let mut policy =
        <PartPolicy as TryFromBytes>::try_read_from_bytes(&known_good_part_policy(pota.raw_pub()))
            .expect("known-good partition policy should decode");
    policy.sata_pub_key = PolicyPubKey::new(
        PolicyKeyKind::Ecc384,
        POLICY_MAX_KEY_LEN as u16,
        sata.raw_pub(),
    );
    assert_eq!(
        info.pid.len(),
        policy.backup_part_id.len(),
        "PartInfo PID should have the expected length",
    );
    policy.backup_part_id.copy_from_slice(&info.pid);
    let mut backup_part_pub = [0u8; POLICY_MAX_KEY_LEN];
    assert_eq!(
        info.pid_pub_key.len(),
        backup_part_pub.len(),
        "PartInfo PID public key should have the expected length",
    );
    backup_part_pub.copy_from_slice(&info.pid_pub_key);
    policy.backup_part_pub_key = PolicyPubKey::new(
        PolicyKeyKind::Ecc384,
        POLICY_MAX_KEY_LEN as u16,
        backup_part_pub,
    );
    let mut policy_bytes = [0u8; PART_POLICY_LEN];
    policy_bytes.copy_from_slice(policy.as_bytes());

    let init = ctx
        .part_init(session, &mach_seed(), &policy_bytes, &pota_thumbprint())
        .expect("PartInit should succeed");
    let pta_chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(session, &policy_bytes, &[], &pta_chain.der_items())
        .expect("PartFinal should succeed");

    let sealing_key = ctx
        .tbor(&TborSdSealingKeyGenReq {
            session_id: session.session_id,
            scope: KEY_SCOPE_LOCAL,
        })
        .expect("local SD sealing-key generation should succeed");
    let report = ctx
        .tbor(&TborKeyReportReq {
            session_id: session.session_id,
            masked_key: sealing_key.masked_key.to_vec(),
            report_data: [0u8; KEY_REPORT_DATA_LEN],
        })
        .expect("sealing-key report generation should succeed");

    let mut sealing_pub = [0u8; RAW_PUB_LEN];
    for (dst, src) in sealing_pub[..48]
        .iter_mut()
        .zip(sealing_key.pub_key[..48].iter().rev())
    {
        *dst = *src;
    }
    for (dst, src) in sealing_pub[48..]
        .iter_mut()
        .zip(sealing_key.pub_key[48..].iter().rev())
    {
        *dst = *src;
    }

    let receiver = make_chain(&sata, &sealing_pub);
    let manufacturer = make_chain(&CaKey::generate(), &pid_pub);
    let owner = make_chain(&CaKey::generate(), &pid_pub);
    let partition_owner = make_chain(&sata, &pid_pub);
    let mut oob_items = Vec::new();
    let receiver_chain = vec![
        add_evidence_item(&mut oob_items, &receiver.root_der),
        add_evidence_item(&mut oob_items, &receiver.leaf_der),
    ];
    let manufacturer_chain = vec![
        add_evidence_item(&mut oob_items, &manufacturer.root_der),
        add_evidence_item(&mut oob_items, &manufacturer.leaf_der),
    ];
    let owner_chain = vec![
        add_evidence_item(&mut oob_items, &owner.root_der),
        add_evidence_item(&mut oob_items, &owner.leaf_der),
    ];
    let partition_owner_chain = vec![
        add_evidence_item(&mut oob_items, &partition_owner.root_der),
        add_evidence_item(&mut oob_items, &partition_owner.leaf_der),
    ];
    let report_descriptor = add_evidence_item(&mut oob_items, &report.report);
    let oob = oob_items.iter().map(Vec::as_slice).collect::<Vec<_>>();

    let req = TborSdCreateRemoteBackupReq {
        session_id: session.session_id,
        masked_sealing_key: sealing_key.masked_key,
        receiver_cert_chain: receiver_chain,
        receiver_mfgr_cert_chain: manufacturer_chain,
        receiver_owner_cert_chain: owner_chain,
        receiver_part_owner_cert_chain: partition_owner_chain,
        receiver_report: ReportDescriptor {
            index: report_descriptor.index,
            length: report_descriptor.length,
        },
        policy,
    };
    ctx.tbor_oob(&req, &oob)
        .expect("test security-domain creation should succeed");
}
