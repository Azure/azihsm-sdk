// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_test_harness::SessionHandshake;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_test_harness::x509_fixture::CaKey;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_chain;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use azihsm_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use azihsm_ddi_tbor_test_harness::x509_fixture::RAW_PUB_LEN;
use azihsm_ddi_tbor_types::*;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use zerocopy::IntoBytes;
use zerocopy::TryFromBytes;

/// MBOR key availability. TBOR key-generation responses are masked blobs,
/// not persistent key IDs; this legacy field controls whether a key is
/// generated for the operation.
#[derive(Arbitrary, Debug)]
enum KeyAvailability {
    App,
    Session,
}

/// HMAC hash variant selector. TBOR identifies the variant with a 1-byte
/// `HashAlgo` discriminant instead of the MBOR `HmacKeyType` key-type
/// enum, and derives both the tag length and the valid `HmacGenerateKey`
/// key-length range from it.
#[derive(Arbitrary, Debug)]
enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    fn to_tbor(&self) -> u8 {
        match self {
            Self::Sha256 => HMAC_HASH_SHA256,
            Self::Sha384 => HMAC_HASH_SHA384,
            Self::Sha512 => HMAC_HASH_SHA512,
        }
    }

    fn tag_len(&self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Map a fuzzed byte into this variant's valid `HmacGenerateKey`
    /// key-length range (SHA-256: 32-64, SHA-384: 48-128, SHA-512: 64-128).
    fn valid_key_length(&self, fuzzed_length: u8) -> u8 {
        let (min, max) = match self {
            Self::Sha256 => (32, 64),
            Self::Sha384 => (48, 128),
            Self::Sha512 => (64, 128),
        };
        min + (fuzzed_length % (max - min + 1))
    }
}

/// `HmacGenerateKey` key scope (wire `KeyScope` discriminant).
#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum KeyScope {
    Unspecified,
    Session,
    Ephemeral,
    Local,
    SecurityDomain,
    Internal,
}

impl KeyScope {
    fn to_tbor(self) -> u8 {
        match self {
            Self::Unspecified => common::KEY_SCOPE_UNSPECIFIED,
            Self::Session => common::KEY_SCOPE_SESSION,
            Self::Ephemeral => common::KEY_SCOPE_EPHEMERAL,
            Self::Local => common::KEY_SCOPE_LOCAL,
            Self::SecurityDomain => common::KEY_SCOPE_SECURITY_DOMAIN,
            Self::Internal => common::KEY_SCOPE_INTERNAL,
        }
    }
}

/// Maximum `HmacGenerateKey` `key_label` length accepted by the device
/// (see [`TborHmacGenerateKeyReq::key_label`]).
const HMAC_KEY_LABEL_MAX_LEN: usize = 128;

/// Bound a fuzzed key label to the command's documented maximum length
/// so a valid request never gets rejected purely for an oversized label.
fn bounded_key_label(label: &[u8]) -> Vec<u8> {
    let len = label.len() % (HMAC_KEY_LABEL_MAX_LEN + 1);
    label[..len].to_vec()
}

/// Fuzz input corresponding to the MBOR `Hmac` target.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Generate a valid HMAC key when the legacy availability setting can
    /// be represented by TBOR.
    use_valid_key_id: bool,
    /// Legacy key availability; TBOR's caller-held masked keys have no App
    /// key-ID lifecycle equivalent.
    key_availability: KeyAvailability,
    /// Hash variant used for valid key generation; also folds in the
    /// legacy `hash_algorithm` field, since TBOR's `HmacGenerateKey`
    /// carries a single hash selector for both.
    hash_algorithm: HashAlgorithm,
    /// Scope requested for `HmacGenerateKey`.
    key_scope: KeyScope,
    /// Caller-supplied key label for `HmacGenerateKey`, bounded to the
    /// command's documented maximum length.
    key_label: Vec<u8>,
    /// Request parameters corresponding to the MBOR request.
    cmdreq_data: FuzzHmacReq,
}

#[derive(Arbitrary, Debug)]
struct FuzzHmacReq {
    /// Legacy MBOR key ID, folded into the arbitrary masked-key bytes
    /// since TBOR carries the masked key itself instead.
    key_id: u16,
    /// Message to MAC.
    msg: Vec<u8>,
    /// Fuzzed byte mapped into the chosen hash variant's valid
    /// `HmacGenerateKey` key-length range.
    key_length: u8,
    /// Arbitrary masked-key bytes used when a valid key is not generated.
    masked_key: Vec<u8>,
}

/// `KeyScope::Session` discriminant.
fn add_evidence_item(oob_items: &mut Vec<Vec<u8>>, der: &[u8]) -> CertDescriptor {
    let index = u8::try_from(oob_items.len()).expect("evidence count fits descriptor index");
    let length = u16::try_from(der.len()).expect("evidence item length fits descriptor");
    oob_items.push(der.to_vec());
    CertDescriptor {
        index,
        length: length.into(),
    }
}

/// Create a security domain so its masking key is available to
/// `HmacGenerateKey`.
fn create_test_security_domain(ctx: &TestCtx, session: &SessionHandshake) {
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
    let mut policy = <PartPolicy as TryFromBytes>::try_read_from_bytes(
        &common::known_good_part_policy(pota.raw_pub()),
    )
    .expect("known-good partition policy should decode");
    policy.sata_pub_key = PolicyPubKey::new(
        PolicyKeyKind::Ecc384,
        POLICY_MAX_KEY_LEN as u16,
        sata.raw_pub(),
    );
    policy.backup_part_id.copy_from_slice(&info.pid);
    let mut backup_part_pub = [0u8; POLICY_MAX_KEY_LEN];
    backup_part_pub.copy_from_slice(&info.pid_pub_key);
    policy.backup_part_pub_key = PolicyPubKey::new(
        PolicyKeyKind::Ecc384,
        POLICY_MAX_KEY_LEN as u16,
        backup_part_pub,
    );
    let mut policy_bytes = [0u8; PART_POLICY_LEN];
    policy_bytes.copy_from_slice(policy.as_bytes());

    let init = ctx
        .part_init(
            session,
            &common::mach_seed(),
            &policy_bytes,
            &common::pota_thumbprint(),
        )
        .expect("PartInit should succeed");
    let pta_chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(session, &policy_bytes, &[], &pta_chain.der_items())
        .expect("PartFinal should succeed");

    let sealing_key = ctx
        .tbor(&TborSdSealingKeyGenReq {
            session_id: session.session_id,
            scope: common::KEY_SCOPE_LOCAL,
        })
        .expect("local SD sealing-key generation should succeed");
    let report = ctx
        .tbor(&TborKeyReportReq {
            session_id: session.session_id,
            masked_key: sealing_key.masked_key.to_vec(),
            report_data: [0u8; KEY_REPORT_DATA_LEN],
        })
        .expect("sealing-key report generation should succeed");

    let mfgr = make_chain(&CaKey::generate(), &pid_pub);
    let owner = make_chain(&CaKey::generate(), &pid_pub);
    let part_owner = make_chain(&sata, &pid_pub);
    let mut oob_items = Vec::new();
    let mfgr_chain = vec![
        add_evidence_item(&mut oob_items, &mfgr.root_der),
        add_evidence_item(&mut oob_items, &mfgr.leaf_der),
    ];
    let owner_chain = vec![
        add_evidence_item(&mut oob_items, &owner.root_der),
        add_evidence_item(&mut oob_items, &owner.leaf_der),
    ];
    let part_owner_chain = vec![
        add_evidence_item(&mut oob_items, &part_owner.root_der),
        add_evidence_item(&mut oob_items, &part_owner.leaf_der),
    ];
    let report_descriptor = add_evidence_item(&mut oob_items, &report.report);

    let req = TborSdCreateRemoteBackupReq {
        session_id: session.session_id,
        masked_sealing_key: sealing_key.masked_key,
        receiver_mfgr_cert_chain: mfgr_chain,
        receiver_owner_cert_chain: owner_chain,
        receiver_part_owner_cert_chain: part_owner_chain,
        receiver_report: ReportDescriptor {
            index: report_descriptor.index,
            length: report_descriptor.length,
        },
        policy: <PartPolicy as TryFromBytes>::try_read_from_bytes(&policy_bytes)
            .expect("security-domain policy should decode"),
    };
    let oob = oob_items.iter().map(Vec::as_slice).collect::<Vec<_>>();
    ctx.tbor_oob(&req, &oob)
        .expect("test security-domain creation should succeed");
}

fn fuzzed_masked_key(input: &FuzzHmacReq) -> Vec<u8> {
    let mut masked_key = input.masked_key.clone();
    masked_key.extend_from_slice(&input.key_id.to_le_bytes());
    masked_key
}

/// Bound a fuzzed message to the `Hmac` command's documented maximum
/// length ([`HMAC_MSG_MAX_LEN`]) so a valid request never overflows the
/// 4-KiB TBOR request buffer.
fn bounded_msg(msg: &[u8]) -> Vec<u8> {
    let len = msg.len() % (HMAC_MSG_MAX_LEN + 1);
    msg[..len].to_vec()
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        let generate_valid_key =
            input.use_valid_key_id && matches!(input.key_availability, KeyAvailability::Session);

        let generated_key = if generate_valid_key {
            match input.key_scope {
                KeyScope::Ephemeral | KeyScope::Local => {
                    common::finalize_partition(ctx, &session)
                }
                KeyScope::SecurityDomain => create_test_security_domain(ctx, &session),
                _ => {}
            }

            let scope = input.key_scope.to_tbor();
            let result = ctx.tbor(&TborHmacGenerateKeyReq {
                session_id: session.session_id,
                scope,
                hash_algo: input.hash_algorithm.to_tbor(),
                key_length: input
                    .hash_algorithm
                    .valid_key_length(input.cmdreq_data.key_length),
                key_label: bounded_key_label(&input.key_label),
            });
            match result {
                Ok(resp) => Some(resp.masked_key),
                Err(err @ DdiError::DriverError(_)) => panic!("Crash Detected: {err}"),
                Err(_)
                    if !matches!(
                        input.key_scope,
                        KeyScope::Session
                            | KeyScope::Ephemeral
                            | KeyScope::Local
                            | KeyScope::SecurityDomain
                    ) =>
                {
                    None
                }
                Err(err) => panic!("provisioned HMAC key generation should succeed: {err}"),
            }
        } else {
            None
        };

        let expect_success = generated_key.is_some();
        let masked_key =
            generated_key.unwrap_or_else(|| fuzzed_masked_key(&input.cmdreq_data));

        let msg = bounded_msg(&input.cmdreq_data.msg);

        let req = TborHmacReq {
            session_id: session.session_id,
            masked_key,
            msg,
        };
        let result = ctx.tbor(&req);

        match (&result, expect_success) {
            (Err(err @ DdiError::DriverError(_)), _) => panic!("Crash Detected: {err}"),
            (Ok(resp), true) => {
                assert_eq!(
                    resp.tag.len(),
                    input.hash_algorithm.tag_len(),
                    "tag length must match the hash variant's digest length"
                );
                let tag_again = ctx
                    .tbor(&req)
                    .expect("repeating a valid Hmac request should succeed")
                    .tag;
                assert_eq!(resp.tag, tag_again, "HMAC must be deterministic");
            }
            (Ok(_), false) => {
                panic!("invalid Hmac request unexpectedly succeeded")
            }
            (Err(err), true) => panic!("valid Hmac request failed: {err}"),
            (Err(_), false) => {}
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
