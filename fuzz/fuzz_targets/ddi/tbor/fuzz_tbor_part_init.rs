// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_test_harness::encrypt_mach_seed_envelope;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::SAPOTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::SATA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::TborPartInitReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// 32-byte `mach_seed` plaintext sealed under the active session's
    /// `param_key`; guarantees the wire envelope authenticates so the
    /// FW handler advances past AEAD into the policy/seed pipeline.
    mach_seed: [u8; MACH_SEED_LEN],
    /// Optional post-seal mutation for reject-path coverage.
    envelope_mutation: common::EnvelopeMutation,
    /// Fixed-length fuzzed POTA thumbprint.
    pota_thumbprint: [u8; POTA_THUMBPRINT_LEN],
    /// Fixed-length fuzzed SATA thumbprint.
    sata_thumbprint: [u8; SATA_THUMBPRINT_LEN],
    /// Whether to include a SAPOTA thumbprint (empty = absent).
    sapota_present: bool,
    /// Fixed-length fuzzed SAPOTA thumbprint (used when `sapota_present`).
    sapota_thumbprint: [u8; SAPOTA_THUMBPRINT_LEN],
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        // Fresh-slate CO session under a rotated (non-default) PSK — the
        // gate `PartInit` needs cleared before the fuzzed opcode can fire.
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);

        let sapota_thumbprint = if input.sapota_present {
            input.sapota_thumbprint.to_vec()
        } else {
            Vec::new()
        };

        // Wire-valid PartPolicy — required so the handler advances past
        // policy decode into the envelope/pipeline logic under fuzz.
        // POTA pubkey is a synthetic pattern because `PartInit` records
        // the policy as a claim but never walks the PTA cert chain.
        let policy_bytes = common::known_good_part_policy(common::fill_ecc384_pubkey_pattern(0x10));
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
            assert!(result.is_err(), "PartInit should reject a mutated envelope",);
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
