// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Key-kind length contract.
//!
//! A single O(1) lookup table — indexed directly by the
//! [`HsmVaultKeyKind`] discriminant — is the *only* place that knows how
//! long a key of a given kind is. Every length decision in the vault
//! (create-time validation, storage cost, read-back, `vault_key_len`)
//! resolves through [`key_len`], so there is no per-kind branching
//! scattered through the code.
//!
//! The fixed sizes mirror the reference firmware's
//! `EntryKind::raw_key_blob_size()` and the variable HMAC min/max, so a
//! key stored here is byte-compatible with that firmware. The unit tests
//! pin every entry, so any drift fails the build.

use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;

/// Length contract for one key kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyLen {
    /// Key material is exactly `n` bytes; `key.len()` must equal it.
    Fixed(u16),

    /// Key material length is chosen at creation within `min..=max`. The
    /// actual length is persisted per entry (so read-back is exact).
    Variable {
        /// Minimum accepted length, inclusive.
        min: u16,
        /// Maximum accepted length, inclusive.
        max: u16,
    },

    /// Not a real key kind (`Free` or reserved/unknown discriminant).
    Invalid,
}

impl KeyLen {
    /// Largest byte length a key of this kind can occupy.
    ///
    /// Returns the fixed size for [`Fixed`](KeyLen::Fixed) and the upper
    /// bound for [`Variable`](KeyLen::Variable).
    #[inline]
    pub fn max_len(self) -> Option<u16> {
        match self {
            KeyLen::Fixed(n) => Some(n),
            KeyLen::Variable { max, .. } => Some(max),
            KeyLen::Invalid => None,
        }
    }

    /// Validates a supplied key length against this contract and returns
    /// the length to persist.
    ///
    /// - [`Fixed`](KeyLen::Fixed): `actual` must equal the fixed size.
    /// - [`Variable`](KeyLen::Variable): `actual` must be in `min..=max`.
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] if `actual` violates the contract or the
    ///   kind is [`Invalid`](KeyLen::Invalid).
    #[inline]
    pub fn check(self, actual: usize) -> HsmResult<u16> {
        match self {
            KeyLen::Fixed(n) if actual == usize::from(n) => Ok(n),
            KeyLen::Variable { min, max }
                if (usize::from(min)..=usize::from(max)).contains(&actual) =>
            {
                Ok(actual as u16)
            }
            _ => Err(HsmError::InvalidArg),
        }
    }
}

/// Per-kind length table, indexed by `HsmVaultKeyKind` discriminant.
///
/// Mirrors the reference firmware's `raw_key_blob_size()` (fixed kinds)
/// and var-HMAC min/max. `SessionExPending` holds the in-flight TBOR
/// Pending blob (up to 256).
///
/// # `SessionEx`
///
/// Length-discriminated by session type, so it is modelled as variable.
/// The two legal blobs are built by `session_blob` in
/// `fw/plat/uno/fw/pal/src/session.rs`:
///
/// | Session type          | Layout                                             | Size |
/// | --------------------- | ---------------------------------------------------| ---- |
/// | `PlainText` (CU)      | `api_rev(8) ‖ param_key(32) ‖ masking_key(32)`     | 72   |
/// | `Authenticated` (CO)  | the above `‖ mac_tx(48) ‖ mac_rx(48)`              | 168  |
///
/// so the range is exactly `[72, 168]` — `min` is the CU blob and `max`
/// the CO blob; nothing legal lands in between.
///
/// **Do not derive these from `SESSION_MASKING_KEY_SIZE` (80).** That is
/// the *legacy CBC* masking key used by the MBOR `Session` kind;
/// `SessionEx` uses the 32-byte AES-256-GCM AEAD key
/// ([`SESSION_MASKING_KEY_LEN`]). Using 80 yields the wrong range
/// `[120, 216]`, which this table shipped with once. That failure was
/// role-asymmetric and easy to misread: the CO blob (168) happens to sit
/// inside `[120, 216]` so Crypto-Officer sessions worked, while every
/// Crypto-User blob (72) fell under `min` and was rejected at
/// `vault.create` with `InvalidArg` — surfacing only at
/// `SessionOpenFinish` as `TborStatus::InvalidArg`, long after the
/// handshake crypto had succeeded. `session_ex_range_is_derived_from_pal_layout`
/// pins the range to the PAL constants so it cannot drift back.
static KIND_LEN: [KeyLen; 44] = [
    /* 0  Free                         */ KeyLen::Invalid,
    /* 1  Rsa2kPublic                  */ KeyLen::Fixed(260),
    /* 2  Rsa3kPublic                  */ KeyLen::Fixed(388),
    /* 3  Rsa4kPublic                  */ KeyLen::Fixed(516),
    /* 4  Rsa2kPrivate                 */ KeyLen::Fixed(516),
    /* 5  Rsa3kPrivate                 */ KeyLen::Fixed(772),
    /* 6  Rsa4kPrivate                 */ KeyLen::Fixed(1028),
    /* 7  Rsa2kPrivateCrt              */ KeyLen::Fixed(1284),
    /* 8  Rsa3kPrivateCrt              */ KeyLen::Fixed(1924),
    /* 9  Rsa4kPrivateCrt              */ KeyLen::Fixed(2564),
    /* 10 Ecc256Public                 */ KeyLen::Fixed(64),
    /* 11 Ecc384Public                 */ KeyLen::Fixed(96),
    /* 12 Ecc521Public                 */ KeyLen::Fixed(136),
    /* 13 Ecc256Private                */ KeyLen::Fixed(32),
    /* 14 Ecc384Private                */ KeyLen::Fixed(48),
    /* 15 Ecc521Private                */ KeyLen::Fixed(68),
    /* 16 Aes128                       */ KeyLen::Fixed(16),
    /* 17 Aes192                       */ KeyLen::Fixed(24),
    /* 18 Aes256                       */ KeyLen::Fixed(32),
    /* 19 AesXtsBulk256                */ KeyLen::Fixed(2),
    /* 20 AesGcmBulk256                */ KeyLen::Fixed(2),
    /* 21 AesGcmBulk256Unapproved      */ KeyLen::Fixed(2),
    /* 22 Secret256                    */ KeyLen::Fixed(32),
    /* 23 Secret384                    */ KeyLen::Fixed(48),
    /* 24 Secret521                    */ KeyLen::Fixed(68),
    /* 25 EstablishCred                */ KeyLen::Fixed(144),
    /* 26 SessionEncryption            */ KeyLen::Fixed(144),
    /* 27 Session                      */ KeyLen::Fixed(88),
    /* 28 _HmacSha256                  */ KeyLen::Fixed(32),
    /* 29 _HmacSha384                  */ KeyLen::Fixed(48),
    /* 30 _HmacSha512                  */ KeyLen::Fixed(64),
    /* 31 MaskingKey                   */ KeyLen::Fixed(80),
    /* 32 VarLenHmacSha256             */ KeyLen::Variable { min: 32, max: 64 },
    /* 33 VarLenHmacSha384             */ KeyLen::Variable { min: 48, max: 128 },
    /* 34 VarLenHmacSha512             */ KeyLen::Variable { min: 64, max: 128 },
    /* 35 SessionExPending           */ KeyLen::Variable { min: 32, max: 256 },
    /* 36 SessionEx                    */ KeyLen::Variable { min: 72, max: 168 },
    /* 37 PartitionTrustAnchor         */ KeyLen::Fixed(48),
    /* 38 UniquePartitionSecret */ KeyLen::Fixed(48),
    /* 39 PartitionLocalMaskingKey     */ KeyLen::Fixed(32),
    /* 40 PartitionEphemeralMaskingKey */ KeyLen::Fixed(32),
    /* 41 SdSealing                    */ KeyLen::Fixed(48),
    /* 42 SdMasking                    */ KeyLen::Fixed(32),
    /* 43 SdPartitionOwnerSeed         */ KeyLen::Fixed(48),
];

/// Resolves the length contract for `kind` in O(1).
///
/// # Errors
///
/// - [`HsmError::InvalidArg`] if `kind` is [`Free`](HsmVaultKeyKind::Free).
/// - [`HsmError::InvalidKeyType`] if `kind` is a reserved/unknown
///   discriminant.
#[inline]
pub fn key_len(kind: HsmVaultKeyKind) -> HsmResult<KeyLen> {
    let idx = usize::from(kind.0);
    match KIND_LEN.get(idx).copied().unwrap_or(KeyLen::Invalid) {
        KeyLen::Invalid if kind == HsmVaultKeyKind::Free => Err(HsmError::InvalidArg),
        KeyLen::Invalid => Err(HsmError::InvalidKeyType),
        spec => Ok(spec),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn every_fixed_kind_matches_reference_firmware() {
        // The full raw_key_blob_size table from the reference firmware.
        let table = [
            (HsmVaultKeyKind::Rsa2kPublic, 260),
            (HsmVaultKeyKind::Rsa3kPublic, 388),
            (HsmVaultKeyKind::Rsa4kPublic, 516),
            (HsmVaultKeyKind::Rsa2kPrivate, 516),
            (HsmVaultKeyKind::Rsa3kPrivate, 772),
            (HsmVaultKeyKind::Rsa4kPrivate, 1028),
            (HsmVaultKeyKind::Rsa2kPrivateCrt, 1284),
            (HsmVaultKeyKind::Rsa3kPrivateCrt, 1924),
            (HsmVaultKeyKind::Rsa4kPrivateCrt, 2564),
            (HsmVaultKeyKind::Ecc256Public, 64),
            (HsmVaultKeyKind::Ecc384Public, 96),
            (HsmVaultKeyKind::Ecc521Public, 136),
            (HsmVaultKeyKind::Ecc256Private, 32),
            (HsmVaultKeyKind::Ecc384Private, 48),
            (HsmVaultKeyKind::Ecc521Private, 68),
            (HsmVaultKeyKind::Aes128, 16),
            (HsmVaultKeyKind::Aes192, 24),
            (HsmVaultKeyKind::Aes256, 32),
            (HsmVaultKeyKind::AesXtsBulk256, 2),
            (HsmVaultKeyKind::AesGcmBulk256, 2),
            (HsmVaultKeyKind::AesGcmBulk256Unapproved, 2),
            (HsmVaultKeyKind::Secret256, 32),
            (HsmVaultKeyKind::Secret384, 48),
            (HsmVaultKeyKind::Secret521, 68),
            (HsmVaultKeyKind::EstablishCred, 144),
            (HsmVaultKeyKind::SessionEncryption, 144),
            (HsmVaultKeyKind::Session, 88),
            (HsmVaultKeyKind::_HmacSha256, 32),
            (HsmVaultKeyKind::_HmacSha384, 48),
            (HsmVaultKeyKind::_HmacSha512, 64),
            (HsmVaultKeyKind::MaskingKey, 80),
            (HsmVaultKeyKind::PartitionTrustAnchor, 48),
            (HsmVaultKeyKind::UniquePartitionSecret, 48),
            (HsmVaultKeyKind::PartitionLocalMaskingKey, 32),
            (HsmVaultKeyKind::PartitionEphemeralMaskingKey, 32),
            (HsmVaultKeyKind::SdSealing, 48),
            (HsmVaultKeyKind::SdMasking, 32),
            (HsmVaultKeyKind::SdPartitionOwnerSeed, 48),
        ];
        for (kind, len) in table {
            assert_eq!(key_len(kind), Ok(KeyLen::Fixed(len)), "{kind:?}");
        }
    }

    #[test]
    fn free_is_invalid_arg() {
        assert_eq!(key_len(HsmVaultKeyKind::Free), Err(HsmError::InvalidArg));
    }

    #[test]
    fn unknown_discriminant_is_invalid_key_type() {
        // 200 is well outside the named 0..=41 range.
        assert_eq!(key_len(HsmVaultKeyKind(200)), Err(HsmError::InvalidKeyType));
    }

    #[test]
    fn fixed_lengths_match_reference_firmware() {
        // Spot-check the full fixed table against raw_key_blob_size().
        let cases = [
            (HsmVaultKeyKind::Rsa2kPublic, 260),
            (HsmVaultKeyKind::Rsa4kPrivateCrt, 2564),
            (HsmVaultKeyKind::Ecc256Public, 64),
            (HsmVaultKeyKind::Ecc521Private, 68),
            (HsmVaultKeyKind::Aes128, 16),
            (HsmVaultKeyKind::Aes256, 32),
            (HsmVaultKeyKind::AesXtsBulk256, 2),
            (HsmVaultKeyKind::Secret521, 68),
            (HsmVaultKeyKind::EstablishCred, 144),
            (HsmVaultKeyKind::Session, 88),
            (HsmVaultKeyKind::_HmacSha512, 64),
            (HsmVaultKeyKind::MaskingKey, 80),
            (HsmVaultKeyKind::PartitionTrustAnchor, 48),
            (HsmVaultKeyKind::UniquePartitionSecret, 48),
        ];
        for (kind, len) in cases {
            assert_eq!(key_len(kind), Ok(KeyLen::Fixed(len)), "{kind:?}");
        }
    }

    #[test]
    fn variable_kinds_have_reference_min_max() {
        assert_eq!(
            key_len(HsmVaultKeyKind::VarLenHmacSha256),
            Ok(KeyLen::Variable { min: 32, max: 64 })
        );
        assert_eq!(
            key_len(HsmVaultKeyKind::VarLenHmacSha384),
            Ok(KeyLen::Variable { min: 48, max: 128 })
        );
        assert_eq!(
            key_len(HsmVaultKeyKind::VarLenHmacSha512),
            Ok(KeyLen::Variable { min: 64, max: 128 })
        );
        assert_eq!(
            key_len(HsmVaultKeyKind::SessionEx),
            Ok(KeyLen::Variable { min: 72, max: 168 })
        );
        assert_eq!(
            key_len(HsmVaultKeyKind::SessionExPending),
            Ok(KeyLen::Variable { min: 32, max: 256 })
        );
    }

    /// The `SessionEx` range is not an arbitrary pair of numbers — it is
    /// the size of the two blobs the PAL actually writes. Derive both
    /// from the same `pal_traits` constants `session_blob` uses, so if
    /// any component key length changes this fails here rather than
    /// silently rejecting real sessions on hardware.
    #[test]
    fn session_ex_range_is_derived_from_pal_layout() {
        use azihsm_fw_hsm_pal_traits::SESSION_MAC_DIR_KEY_LEN;
        use azihsm_fw_hsm_pal_traits::SESSION_MASKING_KEY_LEN;
        use azihsm_fw_hsm_pal_traits::SESSION_PARAM_KEY_LEN;

        // `api_rev` prefix on every SessionEx blob (mirrors the uno PAL's
        // private `SESSION_API_REV_SIZE` in `session.rs`).
        const API_REV: usize = 8;

        // PlainText (CU): api_rev ‖ param_key ‖ masking_key
        let cu = API_REV + SESSION_PARAM_KEY_LEN + SESSION_MASKING_KEY_LEN;
        // Authenticated (CO): the CU blob ‖ mac_tx ‖ mac_rx
        let co = cu + 2 * SESSION_MAC_DIR_KEY_LEN;

        assert_eq!(
            key_len(HsmVaultKeyKind::SessionEx),
            Ok(KeyLen::Variable {
                min: cu as u16,
                max: co as u16,
            })
        );
    }

    /// Both real blob sizes must be accepted and the bounds must be
    /// tight. The 72-byte case is the regression guard: the legacy
    /// CBC-derived `min: 120` rejected *every* Crypto-User session at
    /// `vault.create`, which only surfaced at `SessionOpenFinish`.
    #[test]
    fn session_ex_accepts_both_blobs_and_rejects_out_of_range() {
        let len = key_len(HsmVaultKeyKind::SessionEx).unwrap();

        // CU (PlainText) — the size the legacy `min: 120` wrongly rejected.
        assert_eq!(len.check(72), Ok(72));
        // CO (Authenticated).
        assert_eq!(len.check(168), Ok(168));

        // Tight on both sides: nothing outside the two legal blobs.
        assert!(len.check(71).is_err());
        assert!(len.check(169).is_err());
        // The legacy CBC-derived bounds must no longer be honoured.
        assert!(len.check(216).is_err());
    }

    #[test]
    fn check_validates_fixed_and_variable() {
        let aes = key_len(HsmVaultKeyKind::Aes256).unwrap();
        assert_eq!(aes.check(32), Ok(32));
        assert_eq!(aes.check(31), Err(HsmError::InvalidArg));

        let var = key_len(HsmVaultKeyKind::VarLenHmacSha256).unwrap();
        assert_eq!(var.check(32), Ok(32));
        assert_eq!(var.check(48), Ok(48));
        assert_eq!(var.check(64), Ok(64));
        assert_eq!(var.check(31), Err(HsmError::InvalidArg));
        assert_eq!(var.check(65), Err(HsmError::InvalidArg));
    }

    #[test]
    fn max_len_reports_upper_bound() {
        assert_eq!(
            key_len(HsmVaultKeyKind::Aes256).unwrap().max_len(),
            Some(32)
        );
        assert_eq!(
            key_len(HsmVaultKeyKind::VarLenHmacSha512)
                .unwrap()
                .max_len(),
            Some(128)
        );
    }
}
