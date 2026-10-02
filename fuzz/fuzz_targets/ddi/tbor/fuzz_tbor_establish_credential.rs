// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_test_harness::encrypt_mach_seed_envelope;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POLICY_MAX_KEY_LEN;
use azihsm_ddi_tbor_types::POLICY_VERSION_MAJOR;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::PolicyPubKey;
use azihsm_ddi_tbor_types::SATA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::TborPartInitReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Fixed valid POTA thumbprint, mirroring the canonical fixture used by
/// the `PartInit` integration suite.
const VALID_POTA_THUMBPRINT: [u8; POTA_THUMBPRINT_LEN] = {
    let mut v = [0u8; POTA_THUMBPRINT_LEN];
    let mut i = 0;
    while i < POTA_THUMBPRINT_LEN {
        v[i] = 0x80 ^ i as u8;
        i += 1;
    }
    v
};

/// Fixed valid SATA thumbprint, mirroring the canonical fixture used by
/// the `PartInit` integration suite.
const VALID_SATA_THUMBPRINT: [u8; SATA_THUMBPRINT_LEN] = {
    let mut v = [0u8; SATA_THUMBPRINT_LEN];
    let mut i = 0;
    while i < SATA_THUMBPRINT_LEN {
        v[i] = 0x40 ^ i as u8;
        i += 1;
    }
    v
};

/// Fixed valid SAPOTA thumbprint, reusing the canonical SATA fixture
/// shape (SAPOTA thumbprints share the same 48-byte length).
const VALID_SAPOTA_THUMBPRINT: [u8; SATA_THUMBPRINT_LEN] = {
    let mut v = [0u8; SATA_THUMBPRINT_LEN];
    let mut i = 0;
    while i < SATA_THUMBPRINT_LEN {
        v[i] = 0x20 ^ i as u8;
        i += 1;
    }
    v
};

/// Mirror of the firmware `policy::from_bytes` validation: major version
/// must match, POTA/SATA must be Ecc384 keys, SAPOTA/backup keys are
/// either absent or Ecc384, and no reserved flag bits may be set.
fn is_valid_part_policy(policy: &PartPolicy) -> bool {
    fn valid_key(key: &PolicyPubKey, required: bool) -> bool {
        (!required && key.is_empty())
            || (key.kind() == PolicyKeyKind::Ecc384 && key.len() == POLICY_MAX_KEY_LEN)
    }

    policy.version.major == POLICY_VERSION_MAJOR
        && valid_key(&policy.pota_pub_key, true)
        && valid_key(&policy.sata_pub_key, true)
        && valid_key(&policy.sapota_pub_key, false)
        && valid_key(&policy.backup_part_pub_key, false)
        && policy.flags.is_valid()
}

/// Fuzzed base request parameters for the TBOR `PartInit` operation.
#[derive(Arbitrary, Debug)]
pub struct PartInitCmdReqData {
    /// Raw `mach_seed` plaintext. Always sealed into a wire-correct
    /// AEAD-GCM envelope (canonical session-bound AAD), which is then
    /// optionally corrupted by [`FuzzInput::envelope_mutation`].
    pub mach_seed: [u8; MACH_SEED_LEN],
    /// Raw 484-byte `part_policy` blob.
    pub part_policy: [u8; PART_POLICY_LEN],
    /// Raw 48-byte `pota_thumbprint`.
    pub pota_thumbprint: [u8; POTA_THUMBPRINT_LEN],
    /// Raw 48-byte `sata_thumbprint`.
    pub sata_thumbprint: [u8; SATA_THUMBPRINT_LEN],
    /// Optional raw 48-byte `sapota_thumbprint`.
    pub sapota_thumbprint: Option<[u8; SATA_THUMBPRINT_LEN]>,
}

/// Fuzz input for the TBOR `PartInit` DDI op (the TBOR equivalent of
/// the MBOR `EstablishCredential` op: both bootstrap a partition's
/// initial trust material from inside a freshly-authenticated
/// Crypto-Officer session).
#[derive(Arbitrary, Debug)]
pub struct FuzzInput {
    /// Post-seal mutation applied to the wire-valid 100-byte
    /// `mach_seed` envelope. Mutating a valid envelope (rather than
    /// shipping raw bytes) keeps the length gate satisfied for
    /// `FlipByte`, so malformed headers, AAD, ciphertext, and tags reach
    /// the device-side envelope parser.
    pub envelope_mutation: common::EnvelopeMutation,
    /// If `true`, the fuzz test will use a wire-correct 484-byte
    /// `part_policy` blob instead of `cmdreq_data.part_policy`.
    pub use_valid_part_policy: bool,
    /// If `true`, the fuzz test will use a fixed valid value for the
    /// `pota_thumbprint` field instead of `cmdreq_data.pota_thumbprint`.
    pub use_valid_pota_thumbprint: bool,
    /// If `true`, the fuzz test will use a fixed valid value for the
    /// `sata_thumbprint` field instead of `cmdreq_data.sata_thumbprint`.
    pub use_valid_sata_thumbprint: bool,
    /// If `true`, the fuzz test will use a fixed valid value for the
    /// `sapota_thumbprint` field instead of
    /// `cmdreq_data.sapota_thumbprint`.
    pub use_valid_sapota_thumbprint: bool,
    /// A fuzzed `PartInitCmdReqData` structure that provides the base
    /// for request parameters for the `PartInit` operation.
    pub cmdreq_data: PartInitCmdReqData,
}

fuzz_target!(|input: FuzzInput| {
    fuzz_tbor_establish_credential(input);
});

pub fn fuzz_tbor_establish_credential(input: FuzzInput) {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        // `PartInit` is a CO-session command; bootstrap and
        // authenticate a CO session the same way the `PartInit`
        // integration suite does (rotating off the public default PSK
        // so the request clears the default-PSK reject arm).
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);

        let mut mach_seed_envelope =
            encrypt_mach_seed_envelope(&session, &input.cmdreq_data.mach_seed)
                .expect("mach_seed envelope should seal");
        // Snapshot no-op-ness against the pre-mutation envelope.
        let envelope_is_valid = input.envelope_mutation.is_noop(&mach_seed_envelope);
        input.envelope_mutation.apply(&mut mach_seed_envelope);

        let part_policy_bytes = if input.use_valid_part_policy {
            common::known_good_part_policy(common::fill_ecc384_pubkey_pattern(0x10))
        } else {
            input.cmdreq_data.part_policy
        };
        let part_policy =
            <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&part_policy_bytes)
                .unwrap_or_else(|_| PartPolicy::zeroed());

        let pota_thumbprint = if input.use_valid_pota_thumbprint {
            VALID_POTA_THUMBPRINT
        } else {
            input.cmdreq_data.pota_thumbprint
        };

        let sata_thumbprint = if input.use_valid_sata_thumbprint {
            VALID_SATA_THUMBPRINT
        } else {
            input.cmdreq_data.sata_thumbprint
        };

        let sapota_thumbprint = if input.use_valid_sapota_thumbprint {
            VALID_SAPOTA_THUMBPRINT.to_vec()
        } else {
            input
                .cmdreq_data
                .sapota_thumbprint
                .map(|v| v.to_vec())
                .unwrap_or_default()
        };

        // `PartInit` succeeds only with an unmutated (authentic) `mach_seed`
        // envelope and a well-formed policy; thumbprints are opaque, and
        // SAPOTA is either absent or exactly 48 bytes, so neither affects
        // validity.
        let expect_success = envelope_is_valid && is_valid_part_policy(&part_policy);

        let req = TborPartInitReq {
            session_id: session.session_id,
            mach_seed_envelope,
            part_policy,
            pota_thumbprint,
            sata_thumbprint,
            sapota_thumbprint,
        };

        let resp = ctx.tbor(&req);

        match (&resp, expect_success) {
            (Err(err @ DdiError::DriverError(_)), _) => panic!("Crash Detected: {err}"),
            (Ok(resp), true) => {
                assert!(!resp.pta_csr.is_empty(), "PartInit must return a PTA CSR");
                assert!(
                    !resp.pta_report.is_empty(),
                    "PartInit must return a PTA report"
                );
            }
            (Ok(resp), false) => {
                panic!("invalid PartInit request unexpectedly succeeded: {resp:?}")
            }
            (Err(err), true) => panic!("valid PartInit request failed: {err}"),
            (Err(_), false) => {}
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
}
