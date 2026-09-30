// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_tbor_test_harness::SessionOpenInitOptions;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::encrypt_mach_seed_envelope;
use azihsm_ddi_tbor_types::MACH_SEED_ENVELOPE_MAX_LEN;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POLICY_VERSION_MAJOR;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::PSK_LEN;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::SAPOTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::SATA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborPartInitReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const CO: u8 = 0;

/// Non-default CO PSK used to clear the default-PSK gate before `PartInit`.
const ROTATED_CO_PSK: [u8; PSK_LEN] = [
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
    0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
];

fn bounded_appended_bytes(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let len = usize::arbitrary(u)? % (MACH_SEED_ENVELOPE_MAX_LEN + 1);
    Ok(u.bytes(len)?.to_vec())
}

/// Post-seal mutation applied to the wire-valid `mach_seed_envelope`.
///
/// `None` ships the sealed envelope untouched so the handler advances
/// past AEAD authentication into the policy / thumbprint / seed
/// pipeline. The other variants exercise AEAD-reject and length-reject
/// paths without leaving them buried under negligible-probability
/// arbitrary-byte inputs.
#[derive(Arbitrary, Debug)]
enum EnvelopeMutation {
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
    fn apply(&self, envelope: &mut Vec<u8>) {
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
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// 32-byte `mach_seed` plaintext sealed under the active session's
    /// `param_key`; guarantees the wire envelope authenticates so the
    /// FW handler advances past AEAD into the policy/seed pipeline.
    mach_seed: [u8; MACH_SEED_LEN],
    /// Optional post-seal mutation for reject-path coverage.
    envelope_mutation: EnvelopeMutation,
    /// Fixed-length fuzzed POTA thumbprint.
    pota_thumbprint: [u8; POTA_THUMBPRINT_LEN],
    /// Fixed-length fuzzed SATA thumbprint.
    sata_thumbprint: [u8; SATA_THUMBPRINT_LEN],
    /// Whether to include a SAPOTA thumbprint (empty = absent).
    sapota_present: bool,
    /// Fixed-length fuzzed SAPOTA thumbprint (used when `sapota_present`).
    sapota_thumbprint: [u8; SAPOTA_THUMBPRINT_LEN],
}

/// Build a wire-valid `PartPolicy` blob that clears FW policy validation:
/// `version.major == POLICY_VERSION_MAJOR` and populated Ecc384 POTA + SATA
/// trust anchors. SAPOTA and backup-partition slots are left absent.
///
/// Mirrors `known_good_part_policy` in the integration test suite; kept
/// in-lined here because that helper is `pub(crate)` to the tests module.
fn known_good_part_policy() -> [u8; PART_POLICY_LEN] {
    const OFF_POTA: usize = 2;
    const OFF_SATA: usize = 102;
    const OFF_FLAGS: usize = 418;
    const OFF_INFO: usize = 419;

    fn write_pubkey(bytes: &mut [u8], off: usize, fill: u8) {
        bytes[off..off + 2].copy_from_slice(&PolicyKeyKind::Ecc384.0.to_le_bytes());
        bytes[off + 2..off + 4].copy_from_slice(&96u16.to_le_bytes());
        for (i, b) in bytes[off + 4..off + 4 + 96].iter_mut().enumerate() {
            *b = (fill.wrapping_add(i as u8)) | 0x80;
        }
    }

    let mut bytes = [0u8; PART_POLICY_LEN];
    bytes[0] = POLICY_VERSION_MAJOR;
    bytes[1] = 0;
    write_pubkey(&mut bytes, OFF_POTA, 0x10);
    write_pubkey(&mut bytes, OFF_SATA, 0x20);
    bytes[OFF_FLAGS] = 0;
    for b in bytes[OFF_INFO..OFF_INFO + 64].iter_mut() {
        *b = 0xAB;
    }
    bytes
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        ctx.erase().expect("erase should succeed");

        // Rotate the CO PSK to clear the default-PSK gate before PartInit.
        let bootstrap = ctx
            .open_session(CO, SessionType::Authenticated)
            .expect("bootstrap session open should succeed");
        ctx.psk_change(bootstrap.handshake(), &ROTATED_CO_PSK)
            .expect("PSK rotation should succeed");
        bootstrap
            .close()
            .expect("bootstrap session close should succeed");

        // Open a fresh CO session under the rotated PSK.
        let opts =
            SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(&ROTATED_CO_PSK);
        let pending = ctx
            .session_open_init_with_options(opts)
            .expect("session_open_init should succeed");
        let session = ctx
            .session_open_finish(pending)
            .expect("session_open_finish should succeed");

        let sapota_thumbprint = if input.sapota_present {
            input.sapota_thumbprint.to_vec()
        } else {
            Vec::new()
        };

        // Wire-valid PartPolicy — required so the handler advances past
        // policy decode into the envelope/pipeline logic under fuzz.
        let policy_bytes = known_good_part_policy();
        let part_policy =
            <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(&policy_bytes)
                .expect("known_good_part_policy must decode");

        // Seal the fuzzed 32-byte mach_seed under the freshly negotiated
        // param_key so the envelope authenticates; then optionally apply
        // a fuzzed mutation to cover AEAD-reject / length-reject paths.
        let mut mach_seed_envelope = encrypt_mach_seed_envelope(&session, &input.mach_seed)
            .expect("sealing mach_seed under session param_key should succeed");
        input.envelope_mutation.apply(&mut mach_seed_envelope);

        let part_init_req = TborPartInitReq {
            session_id: session.session_id,
            mach_seed_envelope,
            part_policy,
            pota_thumbprint: input.pota_thumbprint,
            sata_thumbprint: input.sata_thumbprint,
            sapota_thumbprint,
        };
        let _ = ctx.tbor(&part_init_req);

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
