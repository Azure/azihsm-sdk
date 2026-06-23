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
/// and var-HMAC min/max. `SessionCu` is length-discriminated by session
/// type (PlainText=168, Authenticated=264) and modelled as variable.
static KIND_LEN: [KeyLen; 38] = [
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
    /* 35 SessionCu                    */ KeyLen::Variable { min: 168, max: 264 },
    /* 36 PartitionTrustAnchor         */ KeyLen::Fixed(48),
    /* 37 PartitionUniqueMachineSecret */ KeyLen::Fixed(48),
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
            (HsmVaultKeyKind::PartitionUniqueMachineSecret, 48),
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
        // 200 is well outside the named 0..=37 range.
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
            (HsmVaultKeyKind::PartitionUniqueMachineSecret, 48),
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
            key_len(HsmVaultKeyKind::SessionCu),
            Ok(KeyLen::Variable { min: 168, max: 264 })
        );
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
