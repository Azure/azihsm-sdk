// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test-only synthetic **v2** `KeyReport` builder for firmware backends
//! that don't yet implement the on-device `TborKeyReport` command.
//!
//! Manticore's `create-sd` FSM parses the OOB report to recover the
//! receiver's public key (`pk_r`) but has no `KeyReport` handler of
//! its own, so tests can't obtain a signed report the normal way. This
//! module builds a wire-format-identical, **unsigned** report that
//! carries `pk_r` in its inner EC2 `COSE_Key` and the SHA-384 policy
//! digest required by reseal. The rest of the payload is zero-filled and
//! the outer `COSE_Sign1` signature is 96 zero bytes.
//!
//! The FW that consumes this report must run with signature and cert-
//! chain verification disabled (behind a compile-time flag on the
//! firmware side). When the real Manticore `KeyReport` FSM lands,
//! delete this helper and switch the tests back to `TborKeyReportReq`.
//!
//! # Payload schema
//!
//! Matches Manticore's in-tree `KeyAttestationReportPayloadV2`
//! (`hsm/src/key_attestation/report.rs`): a 12-entry integer-keyed CBOR
//! map (indices 0-11) whose fields are `version`, `public_key`,
//! `public_key_size`, `flags`, `app_uuid`, `report_data`,
//! `vm_launch_id`, `key_scope`, `partition_id`, `pid_pub_key`,
//! `pota_pub_key`, `policy_digest`.  The outer COSE_Sign1 envelope
//! (tag + protected header + unprotected header + payload bstr +
//! signature bstr) is reused verbatim from the sim.  The FW
//! parser (`KeyAttestationReportV2View::from_evidence` in
//! `hsm/src/key_attestation/report_v2_reader.rs`) accepts this shape
//! when signature and cert-chain verification are disabled.

use azihsm_crypto::HashAlgo;
use azihsm_crypto::HashOp;
use azihsm_ddi_mbor_sim::report::encode_ecc_public;
use azihsm_ddi_mbor_sim::report::CoseSign1Object;
use azihsm_ddi_mbor_sim::report::UnprotectedHeader;
use azihsm_ddi_mbor_sim::report::APP_UUID_SIZE;
use azihsm_ddi_mbor_sim::report::PROTECTED_HEADER;
use azihsm_ddi_mbor_sim::report::PROTECTED_HEADER_SIZE;
use azihsm_ddi_mbor_sim::report::PUBLIC_KEY_MAX_SIZE;
use azihsm_ddi_mbor_sim::report::REPORT_DATA_SIZE;
use azihsm_ddi_mbor_sim::report::SIGNATURE_SIZE;
use azihsm_ddi_mbor_sim::report::VM_LAUNCH_ID_SIZE;
use minicbor::CborLen;
use minicbor::Encode;

/// COSE curve identifier for NIST P-384 (RFC 9053 section 7.1).
const COSE_ELLIPTIC_CURVES_P_384: i8 = 2;

/// SEC1 uncompressed public-key length: `0x04 || X (48) || Y (48)`.
const SEC1_PUB_LEN: usize = 97;

/// P-384 field element length.
const P384_FE_LEN: usize = 48;

/// Manticore v2 report format version
/// (hsm/src/key_attestation/report.rs::REPORT_VERSION_V2).
const REPORT_VERSION_V2: u16 = 2;

/// HSM partition id length (hsm/types/src/hsm.rs::HSM_PARTITION_ID_LEN).
const PARTITION_ID_SIZE: usize = 16;

/// PID / POTA public-key length: SEC1-uncompressed P-384 point.
const PID_PUB_KEY_SIZE: usize = 97;
const POTA_PUB_KEY_SIZE: usize = 97;

/// SHA-384 digest of the unified PartPolicy.
const POLICY_DIGEST_SIZE: usize = 48;

/// Manticore v2 report payload (`KeyAttestationReportPayloadV2` in
/// `hsm/src/key_attestation/report.rs`).  Only `public_key` /
/// `public_key_size` are populated by this fake; every other field
/// is zeroed.  Kept private to this module -- the sim crate does not
/// export a v2 payload struct, so the schema is duplicated here.
#[derive(Encode, CborLen)]
#[cbor(map)]
struct KeyAttestationReportPayloadV2 {
    #[n(0)]
    version: u16,

    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    public_key: [u8; PUBLIC_KEY_MAX_SIZE],

    #[n(2)]
    public_key_size: u16,

    #[n(3)]
    flags: u32,

    #[n(4)]
    #[cbor(with = "minicbor::bytes")]
    app_uuid: [u8; APP_UUID_SIZE],

    #[n(5)]
    #[cbor(with = "minicbor::bytes")]
    report_data: [u8; REPORT_DATA_SIZE],

    #[n(6)]
    #[cbor(with = "minicbor::bytes")]
    vm_launch_id: [u8; VM_LAUNCH_ID_SIZE],

    #[n(7)]
    key_scope: u8,

    #[n(8)]
    #[cbor(with = "minicbor::bytes")]
    partition_id: [u8; PARTITION_ID_SIZE],

    #[n(9)]
    #[cbor(with = "minicbor::bytes")]
    pid_pub_key: [u8; PID_PUB_KEY_SIZE],

    #[n(10)]
    #[cbor(with = "minicbor::bytes")]
    pota_pub_key: [u8; POTA_PUB_KEY_SIZE],

    #[n(11)]
    #[cbor(with = "minicbor::bytes")]
    policy_digest: [u8; POLICY_DIGEST_SIZE],
}

/// Build a synthetic, **unsigned** COSE_Sign1 key-attestation report
/// whose inner EC2 `COSE_Key` carries `pk_r`.
///
/// Returned bytes are byte-format compatible with the AZIHSM simulator's
/// `CoseSign1Object::encode` output -- same tag byte, protected header,
/// payload schema -- with two differences from a real report:
///
/// * the outer `signature` bstr is 96 zero bytes;
/// * all payload fields except `public_key`, `public_key_size`, and
///   `policy_digest` are zeroed (report version = 2, no PID/POTA keys).
///
/// Firmware consuming this report must skip both the ES384 signature
/// check and cert-chain validation for the surrounding evidence.
pub(crate) fn fake_key_report_bytes(pk_r_sec1: &[u8; SEC1_PUB_LEN], policy: &[u8]) -> Vec<u8> {
    assert_eq!(
        pk_r_sec1[0], 0x04,
        "expected SEC1 uncompressed point (0x04 || X || Y)",
    );
    let x = &pk_r_sec1[1..1 + P384_FE_LEN];
    let y = &pk_r_sec1[1 + P384_FE_LEN..SEC1_PUB_LEN];

    // Inner EC2 COSE_Key { 1: 2 (EC2), -1: 2 (P-384), -2: x, -3: y },
    // written into a fixed 525-byte zero-padded bstr. The real encoded
    // length is captured in `public_key_size`.
    let mut public_key = [0u8; PUBLIC_KEY_MAX_SIZE];
    let cose_len = encode_ecc_public(COSE_ELLIPTIC_CURVES_P_384, x, y, &mut public_key)
        .expect("encode_ecc_public into 525-byte buffer must fit");
    let public_key_size = u16::try_from(cose_len).expect("COSE_Key length fits u16");
    let mut policy_digest = [0u8; POLICY_DIGEST_SIZE];
    HashAlgo::sha384()
        .hash(policy, Some(&mut policy_digest))
        .expect("SHA-384 policy digest");

    let payload_struct = KeyAttestationReportPayloadV2 {
        version: REPORT_VERSION_V2,
        public_key,
        public_key_size,
        flags: 0,
        app_uuid: [0u8; APP_UUID_SIZE],
        report_data: [0u8; REPORT_DATA_SIZE],
        vm_launch_id: [0u8; VM_LAUNCH_ID_SIZE],
        key_scope: 0,
        partition_id: [0u8; PARTITION_ID_SIZE],
        pid_pub_key: [0u8; PID_PUB_KEY_SIZE],
        pota_pub_key: [0u8; POTA_PUB_KEY_SIZE],
        policy_digest,
    };
    let mut payload_bytes = vec![0u8; minicbor::len(&payload_struct)];
    minicbor::encode(&payload_struct, payload_bytes.as_mut_slice())
        .expect("encode KeyAttestationReportPayloadV2");

    let cose = CoseSign1Object {
        protected_header: PROTECTED_HEADER,
        unprotected_header: UnprotectedHeader {},
        payload: &payload_bytes,
        signature: [0u8; SIGNATURE_SIZE],
    };
    // COSE_Sign1 envelope: 1 tag byte + array header + protected
    // header bstr + empty unprotected map + payload bstr + signature
    // bstr.  16 bytes covers CBOR array/bstr headers with margin.
    let envelope_max = 1 + 16 + PROTECTED_HEADER_SIZE + payload_bytes.len() + SIGNATURE_SIZE;
    let mut out = vec![0u8; envelope_max];
    let n = cose
        .encode(&mut out)
        .expect("encode tagged COSE_Sign1 v2 into envelope_max buffer");
    out.truncate(n);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: the emitted bytes start with the COSE_Sign1 tag and
    /// contain the (uncompressed) SEC1 X and Y coordinates of the input.
    #[test]
    fn fake_report_wraps_pk_r() {
        let mut pk = [0u8; SEC1_PUB_LEN];
        pk[0] = 0x04;
        for i in 1..1 + P384_FE_LEN {
            pk[i] = i as u8;
        }
        for i in 1 + P384_FE_LEN..SEC1_PUB_LEN {
            pk[i] = (0xff - i) as u8;
        }

        let policy = [0xA5; 32];
        let bytes = fake_key_report_bytes(&pk, &policy);

        assert_eq!(bytes[0], 0xD2, "first byte must be COSE_Sign1 CBOR tag");
        assert!(
            bytes
                .windows(P384_FE_LEN)
                .any(|w| w == &pk[1..1 + P384_FE_LEN]),
            "emitted report must contain the SEC1 X coordinate verbatim",
        );
        assert!(
            bytes
                .windows(P384_FE_LEN)
                .any(|w| w == &pk[1 + P384_FE_LEN..SEC1_PUB_LEN]),
            "emitted report must contain the SEC1 Y coordinate verbatim",
        );
        let mut policy_digest = [0u8; POLICY_DIGEST_SIZE];
        HashAlgo::sha384()
            .hash(&policy, Some(&mut policy_digest))
            .expect("SHA-384 policy digest");
        assert!(
            bytes
                .windows(POLICY_DIGEST_SIZE)
                .any(|window| window == policy_digest),
            "emitted report must contain the policy digest",
        );
    }
}
