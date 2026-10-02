// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Typed, fluent builder for [`PartPolicy`].
//!
//! [`PartPolicy`] is a fixed 484-byte `#[repr(C)]` wire image whose
//! layout is pinned (it is parsed zero-copy and hashed for attestation).
//! Rather than hand-assemble that image by poking raw byte offsets, this
//! builder lets callers set named, typed fields and then [`build`] the
//! owned [`PartPolicy`].
//!
//! The builder lives in the API crate (not the low-level wire-type crate)
//! so that [`build`] can fail with the crate-wide [`HsmError`], keeping
//! error handling consistent with the rest of the API surface.
//!
//! [`build`]: PartPolicyBuilder::build

use azihsm_ddi_tbor_types::POLICY_BACKUP_PART_ID_LEN;
use azihsm_ddi_tbor_types::POLICY_INFO_LEN;
use azihsm_ddi_tbor_types::POLICY_MAX_KEY_LEN;
use azihsm_ddi_tbor_types::POLICY_VERSION_MAJOR;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::PolicyFlags;
use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::PolicyPubKey;
use azihsm_ddi_tbor_types::PolicyVer;

use crate::HsmResult;
use crate::error::HsmError;

/// Fluent builder for [`PartPolicy`].
///
/// Construct one with [`new`](Self::new), set the required POTA and SATA
/// keys and any optional fields through the typed setters, then call
/// [`build`](Self::build) to obtain the
/// owned [`PartPolicy`].  Public-key setters copy the supplied raw bytes
/// into the fixed [`POLICY_MAX_KEY_LEN`] slot and record the active
/// length.  A known key kind must be the exact length the firmware
/// requires (a [`PolicyKeyKind::Ecc384`] key is `X ‖ Y`, i.e. exactly
/// [`POLICY_MAX_KEY_LEN`] bytes); a wrong-length or oversized key is
/// rejected (not truncated): the first such error is captured and
/// surfaced by [`build`](Self::build) as [`HsmError::InvalidArgument`],
/// since emitting a short or truncated key would silently yield a
/// *different* key (or one guaranteed to fail provisioning) while
/// reporting success.
#[derive(Debug, Clone)]
pub struct PartPolicyBuilder {
    policy: PartPolicy,
    error: Option<HsmError>,
}

impl PartPolicyBuilder {
    /// Start a new builder.
    ///
    /// Seeds [`version`](PartPolicy::version) to a major version of
    /// [`POLICY_VERSION_MAJOR`] and `minor = 0`, leaving every other field
    /// zeroed. POTA and SATA keys must be set before building.
    pub fn new() -> Self {
        let mut policy = PartPolicy::zeroed();
        policy.version = PolicyVer {
            major: POLICY_VERSION_MAJOR,
            minor: 0,
        };
        Self {
            policy,
            error: None,
        }
    }

    /// Build a [`PolicyPubKey`] slot from a discriminant and raw key
    /// bytes, copying them into the fixed [`POLICY_MAX_KEY_LEN`] slot and
    /// recording the active length.
    ///
    /// Enforces the exact on-wire length the firmware requires for a
    /// *known* key kind (a [`PolicyKeyKind::Ecc384`] key is `X ‖ Y`, so
    /// exactly [`POLICY_MAX_KEY_LEN`] bytes); firmware unconditionally
    /// rejects every other length, so accepting a short key here would
    /// report success for a policy guaranteed to fail provisioning.  For
    /// unknown/future key kinds the exact length is not known, so only the
    /// slot-capacity bound is enforced.  Oversized input is rejected
    /// rather than truncated (truncation would yield a different key).
    fn make_key(kind: PolicyKeyKind, raw: &[u8]) -> HsmResult<PolicyPubKey> {
        match kind {
            PolicyKeyKind::Ecc384 => {
                if raw.len() != POLICY_MAX_KEY_LEN {
                    return Err(HsmError::InvalidArgument);
                }
            }
            _ => {
                if raw.len() > POLICY_MAX_KEY_LEN {
                    return Err(HsmError::InvalidArgument);
                }
            }
        }
        let mut data = [0u8; POLICY_MAX_KEY_LEN];
        data[..raw.len()].copy_from_slice(raw);
        Ok(PolicyPubKey::new(kind, raw.len() as u16, data))
    }

    /// Record the first builder error, preserving an earlier one.
    fn record(&mut self, err: HsmError) {
        if self.error.is_none() {
            self.error = Some(err);
        }
    }

    /// Set the policy version (`major.minor`).
    ///
    /// An unsupported major version is rejected by [`build`](Self::build).
    /// Any minor version is accepted.
    pub fn version(mut self, major: u8, minor: u8) -> Self {
        self.policy.version = PolicyVer { major, minor };
        self
    }

    /// Set the POTA (Partition Owner Trust Anchor) public key.
    pub fn pota_key(mut self, kind: PolicyKeyKind, raw: &[u8]) -> Self {
        match Self::make_key(kind, raw) {
            Ok(key) => self.policy.pota_pub_key = key,
            Err(err) => self.record(err),
        }
        self
    }

    /// Set the SATA (Sealing Authority Trust Anchor) public key.
    pub fn sata_key(mut self, kind: PolicyKeyKind, raw: &[u8]) -> Self {
        match Self::make_key(kind, raw) {
            Ok(key) => self.policy.sata_pub_key = key,
            Err(err) => self.record(err),
        }
        self
    }

    /// Set the SAPOTA (Sealing Authority's POTA) public key.
    pub fn sapota_key(mut self, kind: PolicyKeyKind, raw: &[u8]) -> Self {
        match Self::make_key(kind, raw) {
            Ok(key) => self.policy.sapota_pub_key = key,
            Err(err) => self.record(err),
        }
        self
    }

    /// Set the backing-partition identifier (zero-padded to
    /// [`POLICY_BACKUP_PART_ID_LEN`]).  Oversized input is rejected via
    /// [`build`](Self::build).
    pub fn backup_part_id(mut self, id: &[u8]) -> Self {
        if id.len() > POLICY_BACKUP_PART_ID_LEN {
            self.record(HsmError::InvalidArgument);
        } else {
            self.policy.backup_part_id = [0; POLICY_BACKUP_PART_ID_LEN];
            self.policy.backup_part_id[..id.len()].copy_from_slice(id);
        }
        self
    }

    /// Set the backing-partition public key.
    pub fn backup_part_pub_key(mut self, kind: PolicyKeyKind, raw: &[u8]) -> Self {
        match Self::make_key(kind, raw) {
            Ok(key) => self.policy.backup_part_pub_key = key,
            Err(err) => self.record(err),
        }
        self
    }

    /// Set the caller-provided opaque `info` (zero-padded to
    /// [`POLICY_INFO_LEN`]).  Oversized input is rejected via
    /// [`build`](Self::build).
    pub fn info(mut self, info: &[u8]) -> Self {
        if info.len() > POLICY_INFO_LEN {
            self.record(HsmError::InvalidArgument);
        } else {
            self.policy.info = [0; POLICY_INFO_LEN];
            self.policy.info[..info.len()].copy_from_slice(info);
        }
        self
    }

    /// Replace the policy flags wholesale.
    ///
    /// Reserved bits are rejected by [`build`](Self::build).
    pub fn flags(mut self, flags: PolicyFlags) -> Self {
        self.policy.flags = flags;
        self
    }

    /// Set the `include_fmc_cdi` flag.
    pub fn include_fmc_cdi(mut self, value: bool) -> Self {
        self.policy.flags = self.policy.flags.with_include_fmc_cdi(value);
        self
    }

    /// Set the `require_trusted_sa_key` flag.
    pub fn require_trusted_sa_key(mut self, value: bool) -> Self {
        self.policy.flags = self.policy.flags.with_require_trusted_sa_key(value);
        self
    }

    /// Set the `allow_peer_cloning` flag.
    pub fn allow_peer_cloning(mut self, value: bool) -> Self {
        self.policy.flags = self.policy.flags.with_allow_peer_cloning(value);
        self
    }

    /// Finish building and return the owned [`PartPolicy`], or
    /// [`HsmError::InvalidArgument`] if a setter was given input that did
    /// not fit its fixed-size slot, or if either required POTA or SATA key
    /// was not set, the major version is unsupported, or a reserved flag
    /// bit is set.
    pub fn build(self) -> HsmResult<PartPolicy> {
        match self.error {
            Some(err) => Err(err),
            None if self.policy.pota_pub_key.is_empty()
                || self.policy.sata_pub_key.is_empty()
                || self.policy.version.major != POLICY_VERSION_MAJOR
                || !self.policy.flags.is_valid() =>
            {
                Err(HsmError::InvalidArgument)
            }
            None => Ok(self.policy),
        }
    }
}

impl Default for PartPolicyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use zerocopy::IntoBytes;

    use super::*;

    #[test]
    fn builder_sets_typed_fields() {
        let pota = [0x11u8; POLICY_MAX_KEY_LEN];
        let policy = PartPolicyBuilder::new()
            .version(POLICY_VERSION_MAJOR, 0)
            .pota_key(PolicyKeyKind::Ecc384, &pota)
            .sata_key(PolicyKeyKind::Ecc384, &pota)
            .backup_part_id(&[0xCD; POLICY_BACKUP_PART_ID_LEN])
            .info(&[0xAB; POLICY_INFO_LEN])
            .allow_peer_cloning(true)
            .build()
            .expect("all fields fit");

        assert_eq!(policy.version.major, POLICY_VERSION_MAJOR);
        assert_eq!(policy.pota_pub_key.kind(), PolicyKeyKind::Ecc384);
        assert_eq!(policy.pota_pub_key.len(), POLICY_MAX_KEY_LEN);
        assert_eq!(policy.pota_pub_key.data, pota);
        assert!(policy.backup_part_id.iter().all(|&b| b == 0xCD));
        assert!(policy.info.iter().all(|&b| b == 0xAB));
        assert!(policy.flags.allow_peer_cloning());

        // Round-trips back through a zero-copy wire view.
        let bytes = IntoBytes::as_bytes(&policy);
        let view = PartPolicy::ref_from_wire(bytes).expect("ref_from_wire");
        assert_eq!(view.pota_pub_key.data, pota);
    }

    #[test]
    fn builder_defaults_version_to_major_one() {
        let key = [0x11; POLICY_MAX_KEY_LEN];
        let policy = PartPolicyBuilder::new()
            .pota_key(PolicyKeyKind::Ecc384, &key)
            .sata_key(PolicyKeyKind::Ecc384, &key)
            .build()
            .expect("required keys fit");
        assert_eq!(policy.version.major, POLICY_VERSION_MAJOR);
        assert_eq!(policy.version.minor, 0);
    }

    #[test]
    fn builder_validates_major_version_and_accepts_any_minor_version() {
        let key = [0x11; POLICY_MAX_KEY_LEN];
        let builder = PartPolicyBuilder::new()
            .pota_key(PolicyKeyKind::Ecc384, &key)
            .sata_key(PolicyKeyKind::Ecc384, &key);

        for major in 0..=u8::MAX {
            let result = builder.clone().version(major, u8::MAX).build();
            if major == POLICY_VERSION_MAJOR {
                assert_eq!(result.expect("supported major").version.minor, u8::MAX);
            } else {
                assert_eq!(result, Err(HsmError::InvalidArgument));
            }
        }
        for minor in 0..=u8::MAX {
            let policy = builder
                .clone()
                .version(POLICY_VERSION_MAJOR, minor)
                .build()
                .expect("any minor version is accepted");
            assert_eq!(policy.version.minor, minor);
        }
    }

    #[test]
    fn builder_validates_all_flag_combinations() {
        let key = [0x11; POLICY_MAX_KEY_LEN];
        let builder = PartPolicyBuilder::new()
            .pota_key(PolicyKeyKind::Ecc384, &key)
            .sata_key(PolicyKeyKind::Ecc384, &key);

        for bits in 0..=u8::MAX {
            let result = builder.clone().flags(PolicyFlags::from_bits(bits)).build();
            if bits & !0x07 == 0 {
                assert_eq!(result.expect("known flags").flags.into_bits(), bits);
            } else {
                assert_eq!(result, Err(HsmError::InvalidArgument));
            }
        }
    }

    #[test]
    fn builder_rejects_missing_required_anchor_keys() {
        let key = [0x11; POLICY_MAX_KEY_LEN];

        assert_eq!(
            PartPolicyBuilder::new().build(),
            Err(HsmError::InvalidArgument)
        );
        assert_eq!(
            PartPolicyBuilder::new()
                .pota_key(PolicyKeyKind::Ecc384, &key)
                .build(),
            Err(HsmError::InvalidArgument)
        );
        assert_eq!(
            PartPolicyBuilder::new()
                .sata_key(PolicyKeyKind::Ecc384, &key)
                .build(),
            Err(HsmError::InvalidArgument)
        );
    }

    #[test]
    fn builder_rejects_oversized_inputs() {
        // Oversized key material is rejected (not truncated), since a
        // truncated key is a *different* key.
        assert_eq!(
            PartPolicyBuilder::new()
                .pota_key(PolicyKeyKind::Ecc384, &[0x11; POLICY_MAX_KEY_LEN + 1])
                .build(),
            Err(HsmError::InvalidArgument)
        );
        assert_eq!(
            PartPolicyBuilder::new()
                .backup_part_id(&[0x22; POLICY_BACKUP_PART_ID_LEN + 1])
                .build(),
            Err(HsmError::InvalidArgument)
        );
        assert_eq!(
            PartPolicyBuilder::new()
                .info(&[0x33; POLICY_INFO_LEN + 1])
                .build(),
            Err(HsmError::InvalidArgument)
        );

        // Exactly-fitting inputs are accepted.
        assert!(
            PartPolicyBuilder::new()
                .pota_key(PolicyKeyKind::Ecc384, &[0x11; POLICY_MAX_KEY_LEN])
                .sata_key(PolicyKeyKind::Ecc384, &[0x11; POLICY_MAX_KEY_LEN])
                .backup_part_id(&[0x22; POLICY_BACKUP_PART_ID_LEN])
                .info(&[0x33; POLICY_INFO_LEN])
                .build()
                .is_ok()
        );
    }

    #[test]
    fn builder_rejects_wrong_length_ecc384_key() {
        // An Ecc384 key is `X ‖ Y` and must be exactly POLICY_MAX_KEY_LEN
        // bytes; the firmware rejects any other length, so a short key
        // that merely "fits" the slot must be rejected here too rather
        // than emitting a policy guaranteed to fail provisioning.
        for len in [0, 1, POLICY_MAX_KEY_LEN - 1] {
            assert_eq!(
                PartPolicyBuilder::new()
                    .pota_key(PolicyKeyKind::Ecc384, &vec![0x11; len])
                    .build(),
                Err(HsmError::InvalidArgument),
                "Ecc384 key of {len} bytes must be rejected"
            );
        }

        // The exact length is accepted.
        assert!(
            PartPolicyBuilder::new()
                .pota_key(PolicyKeyKind::Ecc384, &[0x11; POLICY_MAX_KEY_LEN])
                .sata_key(PolicyKeyKind::Ecc384, &[0x11; POLICY_MAX_KEY_LEN])
                .build()
                .is_ok()
        );
    }
}
