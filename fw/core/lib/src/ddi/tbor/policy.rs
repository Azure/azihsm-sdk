// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Firmware-side parser for the partition policy ([`PartPolicy`]).
//!
//! The canonical byte layout — structs, derives, layout asserts — is
//! defined in [`azihsm_fw_ddi_tbor_types::policy`].  That crate must
//! stay free of firmware deps (`DmaBuf`, `HsmError`), so the
//! validation/parser surface that consumes those primitives lives
//! here as a thin free function over the canonical type.
//!
//! Validation rules (any failure returns [`HsmError::InvalidArg`]):
//!
//! * Buffer length equals [`PART_POLICY_LEN`].
//! * `try_read_from_bytes` succeeds — automatically rejects any
//!   non-canonical byte (needed for canonical hashing into the policy
//!   digest).
//! * `version.major == POLICY_VERSION_MAJOR`; any `version.minor`
//!   accepted (forward-compat).
//! * `pota_pub_key` and `sata_pub_key` are **required** Ecc384 keys.
//! * `sapota_pub_key` and `backup_part_pub_key` are **optional**: a
//!   zero `len` marks them absent; otherwise they must be valid Ecc384
//!   keys.
//! * `flags` sets no reserved bits ([`PolicyFlags::is_valid`]).
//!
//! `backup_part_id` and `info` are opaque caller payload and are not
//! validated.

use azihsm_fw_ddi_tbor_types::policy::PartPolicy;
use azihsm_fw_ddi_tbor_types::policy::PolicyKeyKind;
use azihsm_fw_ddi_tbor_types::policy::PolicyPubKey;
use azihsm_fw_ddi_tbor_types::policy::PART_POLICY_LEN;
use azihsm_fw_ddi_tbor_types::policy::POLICY_MAX_KEY_LEN;
use azihsm_fw_ddi_tbor_types::policy::POLICY_VERSION_MAJOR;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use zerocopy::TryFromBytes;

// Compile-time pin: the `PART_POLICY_LEN` re-exported from
// `azihsm_fw_hsm_pal_traits` (which has no dependency on
// `azihsm_fw_ddi_tbor_types`) must match the canonical
// `azihsm_fw_ddi_tbor_types::policy::PART_POLICY_LEN` byte for byte;
// a mismatch would surface as a runtime `InvalidArg` when the
// `PartInit` handler validates the request's `part_policy` length.
const _: () = assert!(azihsm_fw_hsm_pal_traits::PART_POLICY_LEN == PART_POLICY_LEN);

/// Active prefix length of `PolicyPubKey::data` when `kind` decodes
/// to [`PolicyKeyKind::Ecc384`] — raw P-384 `X ‖ Y` coordinates (no
/// SEC1 `0x04` prefix).
const ECC384_KEY_LEN: usize = POLICY_MAX_KEY_LEN;

/// Validate a single [`PolicyPubKey`] slot.
///
/// When `required` is `false`, a zero `len` is accepted as "absent"
/// (the slot is unused for this policy); any non-zero `len` must still
/// describe a well-formed Ecc384 key.  When `required` is `true`,
/// the slot must always be a well-formed Ecc384 key.
fn validate_pubkey(key: &PolicyPubKey, required: bool) -> HsmResult<()> {
    let kind = key.kind;
    let key_len = key.len as usize;

    if !required && key_len == 0 {
        return Ok(());
    }

    match kind {
        PolicyKeyKind::Ecc384 => {
            if key_len != ECC384_KEY_LEN {
                return Err(HsmError::InvalidArg);
            }
        }
        _ => return Err(HsmError::InvalidArg),
    }
    Ok(())
}

/// Parse and validate a [`PART_POLICY_LEN`]-byte `PartPolicy`
/// resident in DMA-eligible memory.
///
/// Returns an **owned**, naturally-aligned [`PartPolicy`] copied out of
/// `buf` (the struct is alignment-2, so it cannot be safely overlaid on
/// an arbitrarily-aligned wire buffer).  Downstream code that needs the
/// raw bytes for hashing or persistence keeps the original `&DmaBuf` and
/// threads it into the next DMA primitive.
pub fn from_bytes(buf: &DmaBuf) -> HsmResult<PartPolicy> {
    if buf.len() != PART_POLICY_LEN {
        return Err(HsmError::InvalidArg);
    }

    let this = PartPolicy::try_read_from_bytes(buf).map_err(|_| HsmError::InvalidArg)?;

    if this.version.major != POLICY_VERSION_MAJOR {
        return Err(HsmError::InvalidArg);
    }

    // POTA + SATA trust anchors are mandatory; SAPOTA + backing
    // partition keys are optional (absent => zero len).
    validate_pubkey(&this.pota_pub_key, true)?;
    validate_pubkey(&this.sata_pub_key, true)?;
    validate_pubkey(&this.sapota_pub_key, false)?;
    validate_pubkey(&this.backup_part_pub_key, false)?;

    if !this.flags.is_valid() {
        return Err(HsmError::InvalidArg);
    }

    Ok(this)
}
