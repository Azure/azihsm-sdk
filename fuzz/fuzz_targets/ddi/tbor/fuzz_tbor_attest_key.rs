// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_crypto::AesKey;
use azihsm_crypto::AesKeyWrapPadAlgo;
use azihsm_crypto::EccPublicKey;
use azihsm_crypto::EcdsaAlgo;
use azihsm_crypto::Encrypter;
use azihsm_crypto::ExportableKey;
use azihsm_crypto::HashAlgo;
use azihsm_crypto::ImportableKey;
use azihsm_crypto::KeyGenerationOp;
use azihsm_crypto::RsaEncryptAlgo;
use azihsm_crypto::RsaPrivateKey;
use azihsm_crypto::RsaPublicKey;
use azihsm_crypto::VerifyOp;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_test_harness::SessionHandshake;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_test_harness::x509_fixture::CaKey;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use azihsm_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use azihsm_ddi_tbor_types::*;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use x509::X509Certificate;
use x509::X509CertificateOp;

/// Key types generated as masked blobs for the TBOR `KeyReport` request.
#[derive(Arbitrary, Debug)]
enum KeySource {
    EccGenerated(EccCurve),
    BuiltInUnwrappingKey,
    ImportedRsaKey,
    GeneratedAesKey(common::AesKeySize),
    HmacKey(HmacHash),
    GeneratedSecretKey(EccCurve),
}

#[derive(Arbitrary, Debug)]
enum EccCurve {
    P256,
    P384,
    P521,
}

impl EccCurve {
    fn to_tbor(&self) -> u8 {
        match self {
            Self::P256 => ECC_CURVE_P256,
            Self::P384 => ECC_CURVE_P384,
            Self::P521 => ECC_CURVE_P521,
        }
    }

    /// Raw (unpadded) coordinate length in bytes.
    fn coord_len(&self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }
}

#[derive(Arbitrary, Debug)]
enum HmacHash {
    Sha256,
    Sha384,
    Sha512,
}

impl HmacHash {
    fn to_tbor(&self) -> u8 {
        match self {
            Self::Sha256 => HMAC_HASH_SHA256,
            Self::Sha384 => HMAC_HASH_SHA384,
            Self::Sha512 => HMAC_HASH_SHA512,
        }
    }

    fn valid_key_length(&self, fuzzed_length: u8) -> u8 {
        let (min, max) = match self {
            Self::Sha256 => (32, 64),
            Self::Sha384 => (48, 128),
            Self::Sha512 => (64, 128),
        };
        min + (fuzzed_length % (max - min + 1))
    }
}

/// Persisted key scopes whose masking keys `PartFinal` provisions, and
/// therefore the only scopes `KeyReport` can resolve.
#[derive(Arbitrary, Debug)]
enum MaskingScope {
    Ephemeral,
    Local,
}

impl MaskingScope {
    fn to_tbor(&self) -> u8 {
        match self {
            Self::Ephemeral => 0b010,
            Self::Local => 0b011,
        }
    }
}

/// Fuzz input for TBOR `KeyReport` (the TBOR equivalent of MBOR `AttestKey`).
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Generate a supported TBOR key and use its masked blob.
    use_generated_key: bool,
    /// Selects the key generator used when `use_generated_key` is true.
    key_source: KeySource,
    /// Masking scope used for generated keys.
    scope: MaskingScope,
    /// Used as-is when generating is disabled; used to choose a valid
    /// HMAC key length when `key_source` selects HMAC.
    fuzzed_key_data: FuzzKeyReportData,
}

#[derive(Arbitrary, Debug)]
struct FuzzKeyReportData {
    masked_key: Vec<u8>,
    report_data: [u8; KEY_REPORT_DATA_LEN],
    hmac_key_length: u8,
}

const RSA_OAEP_SHA256: u8 = 1;
const COSE_SIGN1_TAG: u8 = 0xD2;
const PID_SIGNATURE_LEN: usize = 96;

/// Outcome the firmware must produce for the masked key being attested.
enum Expected {
    /// Attestable ECC private key; carries the wire-LE `x ‖ y` public key
    /// and the curve's raw coordinate length.
    Report { pub_key: Vec<u8>, coord_len: usize },
    /// Valid masked key of a non-attestable kind.
    UnsupportedKeyType,
    /// Not a valid masked blob (raw fuzz bytes or a public key).
    Rejected,
}

fn mach_seed() -> [u8; MACH_SEED_LEN] {
    core::array::from_fn(|i| 0x40 + i as u8)
}

fn pota_thumbprint() -> [u8; POTA_THUMBPRINT_LEN] {
    core::array::from_fn(|i| 0x80 ^ i as u8)
}

/// Drive `PartInit` → `PartFinal` so the partition is `Initialized`: this
/// provisions the PID key that signs reports plus the Ephemeral/Local
/// masking keys that `KeyReport` unmasks with.
fn finalize_partition(ctx: &TestCtx, session: &SessionHandshake) {
    let pota = CaKey::generate();
    let policy = common::known_good_part_policy(pota.raw_pub());
    let init = ctx
        .part_init(session, &mach_seed(), &policy, &pota_thumbprint())
        .expect("PartInit should succeed");
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(session, &policy, &[], &chain.der_items())
        .expect("PartFinal should succeed");
}

fn generate_masked_key(ctx: &TestCtx, session_id: u16, input: &FuzzInput) -> (Vec<u8>, Expected) {
    let scope = input.scope.to_tbor();
    match &input.key_source {
        KeySource::EccGenerated(curve) => {
            let resp = ctx
                .tbor(&TborEccGenerateKeyReq {
                    session_id,
                    scope,
                    curve: curve.to_tbor(),
                    key_usage: KEY_USAGE_SIGN,
                    key_label: Vec::new(),
                })
                .expect("ECC key generation should succeed");
            let expected = Expected::Report {
                pub_key: resp.pub_key.to_vec(),
                coord_len: curve.coord_len(),
            };
            (resp.masked_key, expected)
        }
        KeySource::BuiltInUnwrappingKey => {
            let pub_key = ctx
                .tbor(&TborGetUnwrappingKeyReq { session_id })
                .expect("get built-in unwrapping public key")
                .pub_key
                .to_vec();
            (pub_key, Expected::Rejected)
        }
        KeySource::ImportedRsaKey => (
            import_rsa_key(ctx, session_id, scope),
            Expected::UnsupportedKeyType,
        ),
        KeySource::GeneratedAesKey(key_size) => {
            let masked_key = ctx
                .tbor(&TborAesGenerateKeyReq {
                    session_id,
                    scope,
                    key_size: key_size.to_tbor(),
                    key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
                    key_label: Vec::new(),
                })
                .expect("AES key generation should succeed")
                .masked_key;
            (masked_key, Expected::UnsupportedKeyType)
        }
        KeySource::HmacKey(hash) => {
            let masked_key = ctx
                .tbor(&TborHmacGenerateKeyReq {
                    session_id,
                    scope,
                    hash_algo: hash.to_tbor(),
                    key_length: hash.valid_key_length(input.fuzzed_key_data.hmac_key_length),
                    key_label: Vec::new(),
                })
                .expect("HMAC key generation should succeed")
                .masked_key;
            (masked_key, Expected::UnsupportedKeyType)
        }
        KeySource::GeneratedSecretKey(curve) => {
            let gen_derive_key = || {
                ctx.tbor(&TborEccGenerateKeyReq {
                    session_id,
                    scope,
                    curve: curve.to_tbor(),
                    key_usage: KEY_USAGE_DERIVE,
                    key_label: Vec::new(),
                })
                .expect("ECDH key generation should succeed")
            };
            let private_key = gen_derive_key();
            let peer_key = gen_derive_key();
            let masked_secret = ctx
                .tbor(&TborEcdhDeriveReq {
                    session_id,
                    scope,
                    masked_key: private_key.masked_key,
                    peer_pub_key: peer_key.pub_key,
                    key_label: Vec::new(),
                })
                .expect("ECDH secret derivation should succeed")
                .masked_secret;
            (masked_secret, Expected::UnsupportedKeyType)
        }
    }
}

fn import_rsa_key(ctx: &TestCtx, session_id: u16, scope: u8) -> Vec<u8> {
    let key = RsaPrivateKey::generate(256).expect("generate host RSA-2048 key");
    let private_der = key.to_vec().expect("export host RSA private key");
    let unwrapping_key = ctx
        .tbor(&TborGetUnwrappingKeyReq { session_id })
        .expect("get built-in unwrapping public key")
        .pub_key;

    // Convert HSM little-endian (n ‖ e) to the crypto crate's big-endian form.
    let mut public_key_be = Vec::with_capacity(unwrapping_key.len());
    public_key_be.extend(unwrapping_key[..256].iter().rev());
    public_key_be.extend(unwrapping_key[256..].iter().rev());
    let public_key =
        RsaPublicKey::from_hsm_bytes(&public_key_be).expect("parse unwrapping public key");

    let kek = [0xA7; 32];
    let mut encrypted_kek = Encrypter::encrypt_vec(
        &mut RsaEncryptAlgo::with_oaep_padding(HashAlgo::sha256(), None),
        &public_key,
        &kek,
    )
    .expect("RSA-OAEP wrap AES key");
    encrypted_kek.reverse();

    let kek = AesKey::from_bytes(&kek).expect("construct AES key-encryption key");
    let encrypted_private_key =
        Encrypter::encrypt_vec(&mut AesKeyWrapPadAlgo::default(), &kek, &private_der)
            .expect("AES-KWP wrap RSA private key");
    let mut wrapped_blob = encrypted_kek;
    wrapped_blob.extend(encrypted_private_key);

    ctx.tbor(&TborUnwrapKeyReq {
        session_id,
        scope,
        key_class: KEY_CLASS_RSA,
        key_usage: KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        oaep_hash_algo: RSA_OAEP_SHA256,
        wrapped_blob,
        key_label: Vec::new(),
    })
    .expect("import host RSA key through UnwrapKey")
    .masked_key
}

/// Read a CBOR item head at `pos`, returning `(major_type, argument)`.
fn cbor_head(buf: &[u8], pos: &mut usize) -> (u8, usize) {
    let initial = buf[*pos];
    *pos += 1;
    let extra = match initial & 0x1F {
        n @ 0..=23 => return (initial >> 5, n as usize),
        24 => 1,
        25 => 2,
        26 => 4,
        other => panic!("unsupported CBOR additional info {other}"),
    };
    let arg = buf[*pos..*pos + extra]
        .iter()
        .fold(0usize, |acc, b| (acc << 8) | *b as usize);
    *pos += extra;
    (initial >> 5, arg)
}

fn cbor_bstr<'a>(buf: &'a [u8], pos: &mut usize) -> &'a [u8] {
    let (major, len) = cbor_head(buf, pos);
    assert_eq!(major, 2, "expected CBOR byte string");
    let bytes = &buf[*pos..*pos + len];
    *pos += len;
    bytes
}

fn push_cbor_bstr(out: &mut Vec<u8>, bytes: &[u8]) {
    match bytes.len() {
        n @ 0..=23 => out.push(0x40 | n as u8),
        n @ 24..=0xFF => out.extend([0x58, n as u8]),
        n => out.extend([0x59, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(bytes);
}

/// Verify a `KeyReport` COSE_Sign1 under the partition's PID public key
/// (slot-0 cert-chain leaf) and check that it binds `report_data` and the
/// attested ECC key's public point.
fn verify_key_report(
    ctx: &TestCtx,
    report: &[u8],
    report_data: &[u8],
    pub_key_le: &[u8],
    coord_len: usize,
) {
    // COSE_Sign1 = 18([ protected, {}, payload, signature ]).
    assert_eq!(
        report.first(),
        Some(&COSE_SIGN1_TAG),
        "report must be tagged COSE_Sign1"
    );
    let mut pos = 1;
    assert_eq!(
        cbor_head(report, &mut pos),
        (4, 4),
        "COSE_Sign1 is a 4-array"
    );
    let protected = cbor_bstr(report, &mut pos);
    assert_eq!(
        cbor_head(report, &mut pos),
        (5, 0),
        "unprotected header is {{}}"
    );
    let payload = cbor_bstr(report, &mut pos);
    let signature = cbor_bstr(report, &mut pos);
    assert_eq!(pos, report.len(), "no trailing bytes after COSE_Sign1");
    assert_eq!(
        signature.len(),
        PID_SIGNATURE_LEN,
        "PID signature is raw P-384 r ‖ s"
    );

    // Sig_structure = [ "Signature1", protected, h'', payload ].
    let mut tbs = vec![0x84, 0x6A];
    tbs.extend_from_slice(b"Signature1");
    push_cbor_bstr(&mut tbs, protected);
    tbs.push(0x40);
    push_cbor_bstr(&mut tbs, payload);

    let info = ctx.cert_chain_info().expect("GetCertChainInfo");
    let num_certs = info.data.num_certs;
    assert!(num_certs >= 1, "cert chain must contain the PID leaf");
    let leaf = ctx
        .get_certificate(num_certs - 1)
        .expect("GetCertificate(PID leaf)");
    let leaf = X509Certificate::from_der(leaf.data.certificate.as_slice())
        .expect("PID leaf parses as X.509");
    let pid_spki = leaf.get_public_key_der().expect("PID leaf SPKI");
    let pid_pub = EccPublicKey::from_bytes(&pid_spki).expect("PID public key imports");
    let verified = VerifyOp::verify(
        &mut EcdsaAlgo::new(HashAlgo::sha384()),
        &pid_pub,
        &tbs,
        signature,
    )
    .expect("PID signature verification should run");
    assert!(
        verified,
        "KeyReport must be signed by the partition PID key"
    );

    let contains = |needle: &[u8]| payload.windows(needle.len()).any(|w| w == needle);
    assert!(
        contains(report_data),
        "report payload must bind report_data"
    );

    // COSE_Key coordinates are big-endian; the wire public key is LE `x ‖ y`.
    let wire_coord_len = pub_key_le.len() / 2;
    let x_be: Vec<u8> = pub_key_le[..coord_len].iter().rev().copied().collect();
    let y_be: Vec<u8> = pub_key_le[wire_coord_len..wire_coord_len + coord_len]
        .iter()
        .rev()
        .copied()
        .collect();
    assert!(contains(&x_be), "report must attest the key's X coordinate");
    assert!(contains(&y_be), "report must attest the key's Y coordinate");
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        finalize_partition(ctx, &session);

        let (masked_key, expected) = if input.use_generated_key {
            generate_masked_key(ctx, session.session_id, &input)
        } else {
            (input.fuzzed_key_data.masked_key.clone(), Expected::Rejected)
        };
        let req = TborKeyReportReq {
            session_id: session.session_id,
            masked_key,
            report_data: input.fuzzed_key_data.report_data,
        };
        let result = ctx.tbor(&req);

        let encodable = req.masked_key.len() <= KEY_REPORT_MASKED_KEY_MAX_LEN;
        match (&result, expected) {
            (Err(err @ DdiError::DriverError(_)), _) => panic!("Crash Detected: {err}"),
            (Err(err), _) if !encodable => assert!(
                matches!(err, DdiError::TborEncodeError),
                "oversized masked key must fail host-side encoding, got {err}"
            ),
            (Ok(resp), Expected::Report { pub_key, coord_len }) => {
                verify_key_report(ctx, &resp.report, &req.report_data, &pub_key, coord_len)
            }
            (Err(err), Expected::Report { .. }) => {
                panic!("KeyReport of a generated ECC key must succeed, got {err}")
            }
            (Err(err), Expected::UnsupportedKeyType) => assert!(
                matches!(err, DdiError::TborStatus(TborStatus::UnsupportedKeyType)),
                "non-ECC masked key must be rejected with UnsupportedKeyType, got {err}"
            ),
            (Err(err), Expected::Rejected) => assert!(
                matches!(err, DdiError::TborStatus(_)),
                "invalid masked key must be rejected by firmware, got {err}"
            ),
            (Ok(resp), _) => {
                panic!("KeyReport unexpectedly succeeded for an invalid key: {resp:?}")
            }
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
