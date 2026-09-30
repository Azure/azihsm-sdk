// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::encrypt_mach_seed_envelope;
use azihsm_ddi_tbor_types::MACH_SEED_ENVELOPE_MAX_LEN;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POLICY_VERSION_MAJOR;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::SAPOTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::SATA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::TborPartInitReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

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

    /// `true` iff this mutation would leave the sealed envelope byte-
    /// identical (matches the `None` variant or a no-op offset/mask/len/
    /// extra choice inside a mutation variant). Drives the "expect
    /// success" classification for the result assertion.
    fn is_noop(&self, envelope: &[u8]) -> bool {
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
        // Fresh-slate CO session under a rotated (non-default) PSK — the
        // gate `PartInit` needs cleared before the fuzzed opcode can fire.
        let session = common::erase_and_open_rotated_co_session(ctx);

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
        // Snapshot noop-ness against the pre-mutation envelope; `apply`
        // mutates it in place immediately after.
        let envelope_is_noop = input.envelope_mutation.is_noop(&mach_seed_envelope);
        input.envelope_mutation.apply(&mut mach_seed_envelope);

        let part_init_req = TborPartInitReq {
            session_id: session.session_id,
            mach_seed_envelope,
            part_policy,
            pota_thumbprint: input.pota_thumbprint,
            sata_thumbprint: input.sata_thumbprint,
            sapota_thumbprint,
        };

        // Classify the fuzzed inputs by deterministic outcome so we can
        // catch bugs where a valid input is rejected or an invalid input
        // is accepted (silent regressions the `let _` discard would hide).
        //
        // * expect_success: envelope is byte-identical to the freshly
        //   sealed one AND the rest of the request is wire/handler-valid
        //   by construction (known-good policy, fixed-length thumbprints,
        //   SAPOTA is 0 or exactly SAPOTA_THUMBPRINT_LEN). The AEAD open
        //   authenticates and the handler runs the provisioning
        //   pipeline through Commit.
        // * expect_failure: a non-noop envelope mutation guarantees
        //   either (a) the encoded envelope overflows
        //   MACH_SEED_ENVELOPE_MAX_LEN and the wire encoder rejects, or
        //   (b) AES-GCM detects the ciphertext/tag/AAD tamper (or the
        //   post-decrypt length mismatch after truncation) and
        //   `AeadEnvelopeAuthFailed` fires. Either surfaces as
        //   `DdiError`.
        let result = ctx.tbor(&part_init_req);

        if envelope_is_noop {
            result.expect(
                "PartInit should succeed with an unmutated envelope and a wire-valid request",
            );
        } else {
            assert!(
                result.is_err(),
                "PartInit should reject a mutated envelope, got Ok({result:?})",
            );
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
