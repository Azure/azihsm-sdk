// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `AesGenerateKey` command.
//!
//! The command generates a random AES key of the requested size and
//! returns it **masked** under the requested scope's masking key — nothing
//! is stored on-device.  Like the other general crypto commands,
//! `AesGenerateKey` is available to both Crypto-Officer and Crypto-User
//! sessions.
//!
//! Coverage:
//! * Happy path per key size (128/192/256) — the masked key has the
//!   expected length (148/156/164 B) and is non-zero; a second call yields
//!   a distinct key.
//! * Every masking-key scope: `Session` (works pre-finalize), `Ephemeral`
//!   / `Local` (provisioned by `PartFinal`).
//! * `SecurityDomain` scope before `CreateSD` → `UnsupportedKeyScope`.
//! * `Ephemeral` scope before `PartFinal` → `InvalidArg`.
//! * Unknown key size → `InvalidArg`.

#![cfg(any(feature = "emu", feature = "mock", feature = "sock"))]
// The shared masked-key helpers/constants below stay available under any
// backend (so the module isn't emu-limited), but only the emu-gated tests
// exercise them today; suppress dead-code noise in non-emu builds.
#![cfg_attr(not(feature = "emu"), allow(dead_code))]

use azihsm_ddi_tbor_types::TborAesGenerateKeyReq;
use azihsm_ddi_tbor_types::AES_KEY_SIZE_128;
use azihsm_ddi_tbor_types::AES_KEY_SIZE_192;
use azihsm_ddi_tbor_types::AES_KEY_SIZE_256;

use crate::harness::TestCtx;

/// `KeyScope` discriminants matching the firmware `HsmKeyScope`.
pub(crate) const SCOPE_SESSION: u8 = 0b001;
pub(crate) const SCOPE_EPHEMERAL: u8 = 0b010;
pub(crate) const SCOPE_LOCAL: u8 = 0b011;
pub(crate) const SCOPE_SECURITY_DOMAIN: u8 = 0b100;

/// Masked-key envelope length for a given AES key length: `header(8) ‖
/// iv(12) ‖ aad(96) ‖ pt(key) ‖ tag(16)`.
fn masked_len(key_len: usize) -> usize {
    8 + 12 + 96 + key_len + 16
}

/// Expected AES key length (bytes) for a wire key-size discriminant.
pub(crate) fn key_len_for_size(size: u8) -> usize {
    match size {
        AES_KEY_SIZE_128 => 16,
        AES_KEY_SIZE_192 => 24,
        AES_KEY_SIZE_256 => 32,
        other => panic!("unexpected key-size discriminant {other}"),
    }
}

/// Generate a masked AES key of `(scope, size)` on `session_id`.
pub(crate) fn generate_key(ctx: &TestCtx, session_id: u16, scope: u8, size: u8) -> Vec<u8> {
    let req = TborAesGenerateKeyReq {
        session_id,
        scope,
        key_size: size,
    };
    ctx.tbor(&req).expect("AesGenerateKey").masked_key
}

/// Happy path for a `(scope, size)` pair: the masked key has the expected
/// length, is non-zero, and a second call yields a distinct blob.
fn roundtrip(ctx: &TestCtx, session_id: u16, scope: u8, size: u8) {
    let masked = generate_key(ctx, session_id, scope, size);
    assert_eq!(
        masked.len(),
        masked_len(key_len_for_size(size)),
        "masked key length must match the requested AES key size",
    );
    assert!(
        masked.iter().any(|&b| b != 0),
        "masked_key must not be all-zero",
    );

    // Each call samples fresh randomness → a distinct masked blob.
    let masked2 = generate_key(ctx, session_id, scope, size);
    assert_ne!(
        masked, masked2,
        "each generation must yield a distinct masked key",
    );
}

#[cfg(feature = "emu")]
mod emu_tests {
    use azihsm_ddi_tbor_types::TborStatus;

    use super::*;
    use crate::commands::part_init::bootstrap_rotated_co;
    use crate::commands::part_init::ROTATED_CO_PSK;
    use crate::commands::sd_sealing_key_gen::finalized_co_session;

    /// Generates every supported AES size under every supported masking-key scope.
    #[test]
    fn aes_generate_key_roundtrip_all_sizes_all_supported_scopes() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        for scope in [SCOPE_SESSION, SCOPE_EPHEMERAL, SCOPE_LOCAL] {
            for size in [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256] {
                roundtrip(&ctx, session.session_id, scope, size);
            }
        }
    }

    /// Verifies Session-scoped generation works for every AES size before `PartFinal`.
    #[test]
    fn aes_generate_key_session_scope_all_sizes_before_finalize() {
        let ctx = TestCtx::new();
        let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

        for size in [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256] {
            roundtrip(&ctx, session.session_id, SCOPE_SESSION, size);
        }
    }

    /// Rejects Ephemeral scope before `PartFinal` for every supported AES size.
    #[test]
    fn aes_generate_key_rejects_ephemeral_before_finalize_all_sizes() {
        let ctx = TestCtx::new();
        let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

        for key_size in [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256] {
            let req = TborAesGenerateKeyReq {
                session_id: session.session_id,
                scope: SCOPE_EPHEMERAL,
                key_size,
            };

            ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
        }
    }

    /// Rejects Local scope before `PartFinal` for every supported AES size.
    #[test]
    fn aes_generate_key_rejects_local_before_finalize_all_sizes() {
        let ctx = TestCtx::new();
        let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

        for key_size in [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256] {
            let req = TborAesGenerateKeyReq {
                session_id: session.session_id,
                scope: SCOPE_LOCAL,
                key_size,
            };

            ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
        }
    }

    /// Rejects SecurityDomain scope for every supported AES key size.
    #[test]
    fn aes_generate_key_rejects_security_domain_scope_all_sizes() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        for key_size in [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256] {
            let req = TborAesGenerateKeyReq {
                session_id: session.session_id,
                scope: SCOPE_SECURITY_DOMAIN,
                key_size,
            };

            ctx.expect_fw_reject(&req, TborStatus::UnsupportedKeyScope);
        }
    }

    /// Rejects minimum and maximum invalid AES key-size discriminants.
    #[test]
    fn aes_generate_key_rejects_unknown_sizes() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        for key_size in [0, u8::MAX] {
            let req = TborAesGenerateKeyReq {
                session_id: session.session_id,
                scope: SCOPE_EPHEMERAL,
                key_size,
            };

            ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
        }
    }

    /// Rejects key-size discriminants adjacent to the supported AES sizes.
    #[test]
    fn aes_generate_key_rejects_adjacent_invalid_sizes() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let valid = [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256];

        let candidates = [
            AES_KEY_SIZE_128.wrapping_sub(1),
            AES_KEY_SIZE_128.wrapping_add(1),
            AES_KEY_SIZE_192.wrapping_sub(1),
            AES_KEY_SIZE_192.wrapping_add(1),
            AES_KEY_SIZE_256.wrapping_sub(1),
            AES_KEY_SIZE_256.wrapping_add(1),
        ];

        for key_size in candidates {
            if valid.contains(&key_size) {
                continue;
            }

            let req = TborAesGenerateKeyReq {
                session_id: session.session_id,
                scope: SCOPE_EPHEMERAL,
                key_size,
            };

            ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
        }
    }

    /// Rejects an invalid AES key size consistently across every supported scope.
    #[test]
    fn aes_generate_key_rejects_invalid_size_for_all_supported_scopes() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        for scope in [SCOPE_SESSION, SCOPE_EPHEMERAL, SCOPE_LOCAL] {
            let req = TborAesGenerateKeyReq {
                session_id: session.session_id,
                scope,
                key_size: 0,
            };

            ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
        }
    }

    /// Rejects an invalid AES key size before `PartFinal` for Session scope.
    #[test]
    fn aes_generate_key_rejects_invalid_size_before_finalize() {
        let ctx = TestCtx::new();
        let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

        let req = TborAesGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_SESSION,
            key_size: 0,
        };

        ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
    }

    /// Rejects invalid key-scope discriminants across every supported AES size.
    #[test]
    fn aes_generate_key_rejects_invalid_scopes_for_all_sizes() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        for scope in [0, u8::MAX] {
            for key_size in [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256] {
                let req = TborAesGenerateKeyReq {
                    session_id: session.session_id,
                    scope,
                    key_size,
                };

                ctx.expect_fw_reject(&req, TborStatus::UnsupportedKeyScope);
            }
        }
    }

    /// Rejects an unknown session ID.
    #[test]
    fn aes_generate_key_rejects_unknown_session() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let unknown_session_id = session.session_id.wrapping_add(1);

        assert_ne!(
            unknown_session_id, session.session_id,
            "unknown session ID must differ from the active session",
        );

        let req = TborAesGenerateKeyReq {
            session_id: unknown_session_id,
            scope: SCOPE_SESSION,
            key_size: AES_KEY_SIZE_256,
        };

        ctx.expect_fw_reject(&req, TborStatus::FileHandleSessionIdDoesNotMatch);
    }

    /// Verifies repeated generations do not reuse an earlier masked-key blob.
    #[test]
    fn aes_generate_key_repeated_generations_are_distinct() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let mut generated = Vec::new();

        for _ in 0..4 {
            let masked = generate_key(&ctx, session.session_id, SCOPE_EPHEMERAL, AES_KEY_SIZE_256);

            assert!(
                generated.iter().all(|previous| previous != &masked),
                "each AesGenerateKey call must return a distinct masked key",
            );

            generated.push(masked);
        }
    }

    /// Verifies repeated generation across every AES size on one active session.
    #[test]
    fn aes_generate_key_multiple_sizes_same_session() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        for _ in 0..3 {
            for size in [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256] {
                roundtrip(&ctx, session.session_id, SCOPE_EPHEMERAL, size);
            }
        }
    }

    /// Verifies different masking scopes return distinct masked-key blobs.
    #[test]
    fn aes_generate_key_different_scopes_return_distinct_masked_blobs() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let session_masked =
            generate_key(&ctx, session.session_id, SCOPE_SESSION, AES_KEY_SIZE_256);

        let ephemeral_masked =
            generate_key(&ctx, session.session_id, SCOPE_EPHEMERAL, AES_KEY_SIZE_256);

        let local_masked = generate_key(&ctx, session.session_id, SCOPE_LOCAL, AES_KEY_SIZE_256);

        assert_ne!(
            session_masked, ephemeral_masked,
            "Session and Ephemeral scopes must not return identical masked blobs",
        );

        assert_ne!(
            session_masked, local_masked,
            "Session and Local scopes must not return identical masked blobs",
        );

        assert_ne!(
            ephemeral_masked, local_masked,
            "Ephemeral and Local scopes must not return identical masked blobs",
        );
    }

    /// Verifies invalid key size takes precedence when both size and scope are invalid.
    #[test]
    fn aes_generate_key_invalid_size_takes_precedence_over_invalid_scope() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let req = TborAesGenerateKeyReq {
            session_id: session.session_id,
            scope: 0,
            key_size: 0,
        };

        ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
    }

    /// Rejects the firmware-reserved `Internal` key-scope discriminant (0b101).    #[test]
    #[test]
    fn aes_generate_key_rejects_internal_scope() {
        let ctx = TestCtx::new();
        let session = finalized_co_session(&ctx);

        let req = TborAesGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_SECURITY_DOMAIN + 1,
            key_size: AES_KEY_SIZE_256,
        };

        ctx.expect_fw_reject(&req, TborStatus::UnsupportedKeyScope);
    }
}
